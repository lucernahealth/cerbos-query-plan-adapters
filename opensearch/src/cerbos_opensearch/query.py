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


def traverse_and_map_operands(operand: dict) -> Any:
    if exp := operand.get("expression"):
        return {"bool": traverse_and_map_operands(exp)}

    operator = operand["operator"]
    child_operands = operand["operands"]

    # if `operator` in ["and", "or"], `child_operands` is a nested list of `expression` dicts (handled at the
    # beginning of this closure)
    if operator == "and":
        return {
            "must": {"filter": [traverse_and_map_operands(o) for o in child_operands]}
        }
    if operator == "or":
        return {
            "should": [traverse_and_map_operands(o) for o in child_operands],
            "minimum_should_match": 1,
        }
    if operator == "not":
        return {"must_not": [traverse_and_map_operands(o) for o in child_operands]}

    # otherwise, they are a list[dict] (len==2), in the form: `[{'variable': 'foo'}, {'value': 'bar'}]`
    # The order of the keys `variable` and `value` is not guaranteed.
    d = {k: v for o in child_operands for k, v in o.items()}
    variable = d["variable"]
    value = d["value"]

    if "request.resource.attr" not in variable:
        raise ValueError(f"Unsupported variable: {variable}")
    variable = variable.replace("request.resource.attr.", "")

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
        # TODO pass in mapping so we know the field type and can generate the right query. For keyword
        # Overall, term should be used for 'keyword' mappings and match should be used for 'text'.
        # return {"filter": {"terms": {variable: value}}}
        return {
            "should": [{"match": {variable: v}} for v in value],
            "minimum_should_match": 1,
        }
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
