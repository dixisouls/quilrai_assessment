"""Unit tests for tool dispatch, business rules and error mapping (no transport)."""

from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import Any

import mcp_types as types
import pytest
from mcp.shared.exceptions import MCPError

from task1_mcp_server.service import CustomerToolService
from task1_mcp_server.store import Customer, InMemoryCustomerStore

ACTIVE = Customer("CUST-00042", "Ada Lovelace", "ada@example.com", "gold", "active", Decimal("100"))
SUSPENDED = Customer(
    "CUST-00666", "Mallory Doe", "mallory@example.com", "standard", "suspended", Decimal("50")
)


@pytest.fixture
def service() -> CustomerToolService:
    return CustomerToolService(InMemoryCustomerStore([ACTIVE, SUSPENDED]))


def _text(result: types.CallToolResult) -> str:
    [block] = result.content
    assert isinstance(block, types.TextContent)
    return block.text


# --- tools/list -----------------------------------------------------------------


def test_lists_exactly_the_two_tools_with_strict_schemas(service: CustomerToolService) -> None:
    tools = {t.name: t for t in service.list_tools()}
    assert set(tools) == {"get_customer_record", "trigger_refund"}
    for tool in tools.values():
        assert tool.description
        assert tool.input_schema["additionalProperties"] is False
        assert tool.output_schema is not None
    assert tools["get_customer_record"].input_schema["required"] == ["customer_id"]
    assert set(tools["trigger_refund"].input_schema["required"]) == {
        "customer_id",
        "amount",
        "reason",
    }


def test_tool_annotations_describe_side_effects(service: CustomerToolService) -> None:
    tools = {t.name: t for t in service.list_tools()}
    read, write = tools["get_customer_record"].annotations, tools["trigger_refund"].annotations
    assert read is not None and read.read_only_hint is True
    assert write is not None and write.read_only_hint is False
    assert write.destructive_hint is True
    assert write.idempotent_hint is False


# --- get_customer_record --------------------------------------------------------


async def test_get_customer_record_returns_structured_and_text(
    service: CustomerToolService,
) -> None:
    result = await service.call("get_customer_record", {"customer_id": "CUST-00042"})
    assert result.is_error is False
    assert result.structured_content == {
        "customer_id": "CUST-00042",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "tier": "gold",
        "status": "active",
        "refundable_balance": "100.00",
    }
    # Text content mirrors the structured content for clients without structured support.
    assert json.loads(_text(result)) == result.structured_content


async def test_unknown_customer_is_a_tool_error_not_a_protocol_error(
    service: CustomerToolService,
) -> None:
    result = await service.call("get_customer_record", {"customer_id": "CUST-99999"})
    assert result.is_error is True
    assert _text(result) == "Customer not found."
    assert result.structured_content is None


# --- trigger_refund -------------------------------------------------------------


async def test_refund_succeeds_and_reduces_balance(service: CustomerToolService) -> None:
    args = {"customer_id": "CUST-00042", "amount": 30.25, "reason": "Duplicate charge on invoice"}
    result = await service.call("trigger_refund", args)
    assert result.is_error is False
    receipt = result.structured_content
    assert receipt is not None
    assert receipt["amount"] == "30.25"
    assert receipt["remaining_refundable_balance"] == "69.75"
    assert receipt["status"] == "accepted"
    assert receipt["refund_id"].startswith("RF-")

    record = await service.call("get_customer_record", {"customer_id": "CUST-00042"})
    assert record.structured_content is not None
    assert record.structured_content["refundable_balance"] == "69.75"


async def test_refund_ids_are_unique(service: CustomerToolService) -> None:
    args = {"customer_id": "CUST-00042", "amount": 1, "reason": "Goodwill credit for delay"}
    ids = set()
    for _ in range(5):
        result = await service.call("trigger_refund", args)
        assert result.structured_content is not None
        ids.add(result.structured_content["refund_id"])
    assert len(ids) == 5


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            {"customer_id": "CUST-99999", "amount": 5, "reason": "Duplicate charge on invoice"},
            "Customer not found.",
        ),
        (
            {"customer_id": "CUST-00666", "amount": 5, "reason": "Duplicate charge on invoice"},
            "Customer account is not active.",
        ),
        (
            {
                "customer_id": "CUST-00042",
                "amount": 100.01,
                "reason": "Duplicate charge on invoice",
            },
            "Refund exceeds the refundable balance.",
        ),
    ],
)
async def test_business_rule_violations_are_tool_errors(
    service: CustomerToolService, args: dict[str, Any], message: str
) -> None:
    result = await service.call("trigger_refund", args)
    assert result.is_error is True
    assert _text(result) == message


async def test_rejected_refund_does_not_change_balance(service: CustomerToolService) -> None:
    args = {"customer_id": "CUST-00042", "amount": 500, "reason": "Duplicate charge on invoice"}
    await service.call("trigger_refund", args)
    record = await service.call("get_customer_record", {"customer_id": "CUST-00042"})
    assert record.structured_content is not None
    assert record.structured_content["refundable_balance"] == "100.00"


# --- Protocol errors (JSON-RPC) -------------------------------------------------


async def test_invalid_arguments_raise_invalid_params(service: CustomerToolService) -> None:
    with pytest.raises(MCPError) as exc:
        await service.call("trigger_refund", {"customer_id": "bad", "amount": -1, "reason": "x"})
    assert exc.value.code == types.INVALID_PARAMS == -32602
    assert exc.value.message == "Invalid params"
    fields = {e["field"] for e in exc.value.data["errors"]}
    assert fields == {"customer_id", "amount", "reason"}


async def test_invalid_params_data_never_echoes_input_values(
    service: CustomerToolService,
) -> None:
    secret = "jane@example.com 4111111111111111"
    with pytest.raises(MCPError) as exc:
        await service.call("get_customer_record", {"customer_id": secret})
    assert "jane@example.com" not in json.dumps(exc.value.data)
    [error] = exc.value.data["errors"]
    assert set(error) == {"field", "message", "type"}


async def test_unknown_fields_are_reported_by_name(service: CustomerToolService) -> None:
    with pytest.raises(MCPError) as exc:
        await service.call("get_customer_record", {"customer_id": "CUST-00042", "x": 1})
    assert exc.value.data["errors"] == [
        {"field": "x", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


@pytest.mark.parametrize("arguments", [None, {}])
async def test_missing_arguments_are_invalid_params(
    service: CustomerToolService, arguments: dict[str, Any] | None
) -> None:
    with pytest.raises(MCPError) as exc:
        await service.call("get_customer_record", arguments)
    assert exc.value.code == types.INVALID_PARAMS


async def test_unknown_tool_is_invalid_params_without_echo(service: CustomerToolService) -> None:
    with pytest.raises(MCPError) as exc:
        await service.call("admin_reset_key<script>", {})
    assert exc.value.code == types.INVALID_PARAMS
    assert exc.value.message == "Unknown tool"
    assert "<script>" not in json.dumps(exc.value.data)
    assert exc.value.data == {"available_tools": ["get_customer_record", "trigger_refund"]}


async def test_unexpected_failure_is_internal_error_without_details(
    service: CustomerToolService, caplog: pytest.LogCaptureFixture
) -> None:
    class ExplodingStore(InMemoryCustomerStore):
        def get(self, customer_id: str) -> Customer | None:
            raise RuntimeError("db password=hunter2 at /srv/db.sqlite")

    broken = CustomerToolService(ExplodingStore([]))
    with caplog.at_level(logging.ERROR), pytest.raises(MCPError) as exc:
        await broken.call("get_customer_record", {"customer_id": "CUST-00042"})
    assert exc.value.code == types.INTERNAL_ERROR == -32603
    assert exc.value.message == "Internal error"
    assert "hunter2" not in json.dumps(exc.value.data)
    correlation_id = exc.value.data["correlation_id"]
    # The operator can find the full detail in server logs (stderr) by correlation id.
    assert any(getattr(r, "correlation_id", None) == correlation_id for r in caplog.records)


async def test_protocol_errors_propagate_unchanged(service: CustomerToolService) -> None:
    class StrictStore(InMemoryCustomerStore):
        def get(self, customer_id: str) -> Customer | None:
            raise MCPError(types.INVALID_REQUEST, "nope")

    with pytest.raises(MCPError) as exc:
        await CustomerToolService(StrictStore([])).call(
            "get_customer_record", {"customer_id": "CUST-00042"}
        )
    assert exc.value.code == types.INVALID_REQUEST
