"""Tool definitions, dispatch, and the mapping from failures to MCP / JSON-RPC errors.

Three failure classes, each with a deliberate wire representation:

=================================  ==========================================
Failure                            Response
=================================  ==========================================
Arguments fail the input schema    JSON-RPC error ``-32602 Invalid params``,
(or the tool name is unknown)      ``data.errors`` = field, message, type.
                                   Input *values* are never echoed (they may
                                   be PII or an injection payload).
Valid input, business rule says    ``CallToolResult(is_error=True)`` with a
no (unknown customer, suspended,   short, fixed message the model can act on.
balance exceeded)                  This is a successful *call* whose outcome is
                                   a refusal, which is MCP's "tool execution
                                   error".
Anything unexpected                JSON-RPC error ``-32603 Internal error``
                                   with only a ``correlation_id``. The
                                   traceback goes to the server log (stderr)
                                   under the same id.
=================================  ==========================================

Why ``-32602`` for bad arguments instead of the SDK's default ``is_error``
result: the assessment requires standard JSON-RPC error codes for invalid
input. It is also the stricter contract: the call never reaches business logic.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final

import mcp_types as types
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel, ValidationError

from quilr_common.log import AuditEvent, Decision, emit_audit, get_logger
from task1_mcp_server.models import (
    CustomerRecord,
    GetCustomerRecordInput,
    RefundReceipt,
    TriggerRefundInput,
)
from task1_mcp_server.store import Customer, CustomerStore, RefundError

log = get_logger(__name__)


class ToolExecutionError(Exception):
    """Valid request, refused outcome. Becomes ``is_error=True`` with ``public_message``."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message)
        self.public_message = public_message


def _money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01'))}"


def _invalid_params(exc: ValidationError) -> MCPError:
    errors = [
        {
            "field": ".".join(str(part) for part in err["loc"]) or "(arguments)",
            "message": err["msg"],
            "type": err["type"],
        }
        for err in exc.errors(include_url=False, include_input=False, include_context=False)
    ]
    return MCPError(types.INVALID_PARAMS, "Invalid params", {"errors": errors})


type Handler = Callable[[Any], Awaitable[BaseModel]]


@dataclass(frozen=True, slots=True)
class _ToolSpec:
    tool: types.Tool
    input_model: type[BaseModel]
    handler: Handler


class CustomerToolService:
    """Owns the tool catalogue and executes calls. Transport-agnostic and unit-testable."""

    def __init__(self, store: CustomerStore) -> None:
        self._store = store
        self._tools: Final[dict[str, _ToolSpec]] = {
            "get_customer_record": _ToolSpec(
                tool=types.Tool(
                    name="get_customer_record",
                    title="Get customer record",
                    description=(
                        "Look up a customer by id (format CUST-XXXXX, five digits) and return "
                        "their profile, account status and refundable balance."
                    ),
                    input_schema=GetCustomerRecordInput.model_json_schema(),
                    output_schema=CustomerRecord.model_json_schema(),
                    annotations=types.ToolAnnotations(
                        read_only_hint=True,
                        destructive_hint=False,
                        idempotent_hint=True,
                        open_world_hint=False,
                    ),
                ),
                input_model=GetCustomerRecordInput,
                handler=self._get_customer_record,
            ),
            "trigger_refund": _ToolSpec(
                tool=types.Tool(
                    name="trigger_refund",
                    title="Trigger refund",
                    description=(
                        "Refund a customer. Moves money: amount in USD (positive, max 2 "
                        "decimals, must not exceed the refundable balance) and a reason of at "
                        "least 10 characters are required. Not idempotent."
                    ),
                    input_schema=TriggerRefundInput.model_json_schema(),
                    output_schema=RefundReceipt.model_json_schema(),
                    annotations=types.ToolAnnotations(
                        read_only_hint=False,
                        destructive_hint=True,
                        idempotent_hint=False,
                        open_world_hint=False,
                    ),
                ),
                input_model=TriggerRefundInput,
                handler=self._trigger_refund,
            ),
        }

    def list_tools(self) -> list[types.Tool]:
        return [spec.tool for spec in self._tools.values()]

    async def call(self, name: str, arguments: Mapping[str, Any] | None) -> types.CallToolResult:
        spec = self._tools.get(name)
        if spec is None:
            # The requested name is attacker-controlled; don't reflect it back.
            raise MCPError(
                types.INVALID_PARAMS, "Unknown tool", {"available_tools": sorted(self._tools)}
            )
        try:
            params = spec.input_model.model_validate(dict(arguments or {}))
        except ValidationError as exc:
            log.info("tool arguments rejected", extra={"tool": name, "errors": exc.error_count()})
            raise _invalid_params(exc) from None

        started = time.perf_counter()
        try:
            output = await spec.handler(params)
        except ToolExecutionError as exc:
            log.info("tool refused", extra={"tool": name, "outcome": exc.public_message})
            return types.CallToolResult(
                content=[types.TextContent(text=exc.public_message)], is_error=True
            )
        except MCPError:
            raise
        except Exception:
            correlation_id = uuid.uuid4().hex
            log.exception("tool crashed", extra={"tool": name, "correlation_id": correlation_id})
            raise MCPError(
                types.INTERNAL_ERROR, "Internal error", {"correlation_id": correlation_id}
            ) from None

        structured = output.model_dump(mode="json")
        log.info(
            "tool succeeded",
            extra={"tool": name, "latency_ms": round((time.perf_counter() - started) * 1000, 2)},
        )
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(structured, separators=(",", ":")))],
            structured_content=structured,
            is_error=False,
        )

    # --- Handlers ---------------------------------------------------------------

    async def _get_customer_record(self, params: GetCustomerRecordInput) -> CustomerRecord:
        customer = self._store.get(params.customer_id)
        if customer is None:
            raise ToolExecutionError("Customer not found.")
        return _record(customer)

    async def _trigger_refund(self, params: TriggerRefundInput) -> RefundReceipt:
        # Amount is safe to record; the free-text reason is not (it may hold PII).
        metadata: dict[str, Any] = {
            "amount": _money(params.amount),
            "reason_chars": len(params.reason),
        }
        try:
            refund = self._store.refund(params.customer_id, params.amount)
        except RefundError as exc:
            emit_audit(
                AuditEvent(
                    action="tool.trigger_refund",
                    decision=Decision.DENY,
                    reason=exc.public_message,
                    resource=params.customer_id,
                    metadata=metadata,
                )
            )
            raise ToolExecutionError(exc.public_message) from None
        emit_audit(
            AuditEvent(
                action="tool.trigger_refund",
                decision=Decision.ALLOW,
                reason="refund accepted",
                resource=params.customer_id,
                metadata={**metadata, "refund_id": refund.refund_id},
            )
        )
        return RefundReceipt(
            refund_id=refund.refund_id,
            customer_id=refund.customer_id,
            amount=_money(refund.amount),
            remaining_refundable_balance=_money(refund.remaining_balance),
        )


def _record(customer: Customer) -> CustomerRecord:
    return CustomerRecord(
        customer_id=customer.customer_id,
        name=customer.name,
        email=customer.email,
        tier=customer.tier,
        status=customer.status,
        refundable_balance=_money(customer.refundable_balance),
    )
