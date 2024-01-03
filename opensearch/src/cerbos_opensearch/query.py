from typing import Any

from cerbos.engine.v1 import engine_pb2
from cerbos.response.v1 import response_pb2
from cerbos.sdk.model import PlanResourcesFilterKind, PlanResourcesResponse
from google.protobuf.json_format import MessageToDict

# We support both the legacy HTTP and gRPC clients, so we need to accept both input types
_deny_types = frozenset(
    [
        PlanResourcesFilterKind.ALWAYS_DENIED,
        engine_pb2.PlanResourcesFilter.KIND_ALWAYS_DENIED,
    ]
)
_allow_types = frozenset(
    [
        PlanResourcesFilterKind.ALWAYS_ALLOWED,
        engine_pb2.PlanResourcesFilter.KIND_ALWAYS_ALLOWED,
    ]
)

_operator_type_mapping = {
    "and": "must",
    "or": "should",
    "not": "must_not",
}


def wrap_in_bool_if_necessary(conditions, operator_type):
    wrapped_conditions = [
        cond if isinstance(cond, dict) and "bool" in cond else {"bool": cond}
        for cond in conditions
    ]
    return {"bool": {operator_type: wrapped_conditions}}


def traverse_and_map_operands(operand: dict) -> Any:
    if exp := operand.get("expression"):
        result = traverse_and_map_operands(exp)
        return (
            result
            if isinstance(result, dict) and "bool" in result
            else {"bool": result}
        )

    operator = operand["operator"]
    child_operands = operand["operands"]

    if operator in _operator_type_mapping.keys():
        operator_type = _operator_type_mapping[operator]

        conditions = [traverse_and_map_operands(o) for o in child_operands]
        wrapped_conditions = wrap_in_bool_if_necessary(conditions, operator_type)

        if operator == "or":
            wrapped_conditions["bool"]["minimum_should_match"] = 1

        return wrapped_conditions

    # Handling other operators
    d = {k: v for o in child_operands for k, v in o.items()}
    variable = d["variable"]
    value = d.get("value")

    if "request.resource.attr" not in variable:
        raise ValueError(f"Unsupported variable: {variable}")
    variable = variable.replace("request.resource.attr.", "")

    # Constructing the appropriate query based on the operator
    if operator == "eq":
        return {"filter": {"term": {variable: value}}}
    elif operator == "ne":
        return {"must_not": {"term": {variable: value}}}
    elif operator == "lt":
        return {"filter": {"range": {variable: {"lt": value}}}}
    elif operator == "gt":
        return {"filter": {"range": {variable: {"gt": value}}}}
    elif operator == "le":
        return {"filter": {"range": {variable: {"lte": value}}}}
    elif operator == "ge":
        return {"filter": {"range": {variable: {"gte": value}}}}
    elif operator == "in":
        # Ensure value is a list for consistent handling (in string vs in list of strings)
        if not value:
            value = []
        values = [value] if isinstance(value, str) else value

        # TODO pass in mapping so we know the field type and can generate the right query. For keyword
        # Overall, term should be used for 'keyword' mappings and match should be used for 'text'.
        # return {"filter": {"terms": {variable: value}}}
        return {
            "bool": {
                "should": [{"match": {variable: v}} for v in values],
                "minimum_should_match": 1,
            }
        }
    elif operator == "hasIntersection":
        if not value:
            value = []
        values = [value] if isinstance(value, str) else value

        q = {"bool": {"should": {"terms": {variable: values}}}}
        return q
    else:
        raise ValueError(f"Unsupported operator: {operator}")


def get_query(
    query_plan: PlanResourcesResponse | response_pb2.PlanResourcesResponse,
) -> Any:
    if query_plan.filter is None or query_plan.filter.kind in _deny_types:
        return {"query": {"bool": {"must_not": {"match_all": {}}}}}

    if query_plan.filter.kind in _allow_types:
        return {"query": {"match_all": {}}}

    cond = (
        MessageToDict(query_plan.filter.condition)
        if isinstance(query_plan, response_pb2.PlanResourcesResponse)
        else query_plan.filter.condition.to_dict()
    )

    return {"query": traverse_and_map_operands(cond)}
