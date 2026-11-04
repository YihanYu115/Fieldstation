import pytest

from issue_manager.conclusion_rule_schema import (
    bounded_rule_errors,
    conclusion_rule_errors,
    validate_conclusion_rule_schema,
)
from issue_manager.errors import ValidationError


def test_rule_schema_reports_missing_and_disallowed_fields():
    schema = validate_conclusion_rule_schema({
        "type": "object", "properties": {"result": {"type": "string"}},
        "required": ["result"], "additionalProperties": False,
    })
    errors = conclusion_rule_errors({"extra": 1}, schema)
    assert {(item["path"], item["code"]) for item in errors} == {
        ("$.structured_outputs.result", "required"),
        ("$.structured_outputs.extra", "unknown"),
    }


def test_rule_schema_is_independent_of_caller_object():
    source = {"type": "object", "properties": {"value": {"type": "integer"}}}
    schema = validate_conclusion_rule_schema(source)
    source["properties"]["value"]["type"] = "string"
    assert conclusion_rule_errors({"value": 1}, schema) == []


def test_rule_error_budget_reports_truncation():
    schema = validate_conclusion_rule_schema({"type": "object", "additionalProperties": False})
    errors = conclusion_rule_errors({f"extra{i}": i for i in range(40)}, schema)
    result = bounded_rule_errors(errors)
    assert result["error_count"] == 40
    assert len(result["field_errors"]) == 32
    assert result["fields_truncated"] is True


@pytest.mark.parametrize("schema", [
    {}, {"type": "array", "items": {"type": "string"}},
    {"type": "object", "required": ["missing"]},
    {"type": "object", "unsupported": True},
    {"type": "object", "description": "x" * 32768},
    {"type": "object", "properties": {"x": {"type": "number", "minimum": "bad"}}},
    {"type": "object", "properties": {"x": {"type": "integer", "minimum": 2, "maximum": 1}}},
    {"type": "object", "properties": {"x": {"type": "array", "items": {}, "minItems": -1}}},
])
def test_invalid_rule_schema_is_rejected(schema):
    with pytest.raises(ValidationError):
        validate_conclusion_rule_schema(schema)
