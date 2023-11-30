import pytest
import logging
import json
from cerbos.sdk.model import (
    PlanResourcesFilter,
    PlanResourcesFilterKind,
    PlanResourcesResponse,
)

from cerbos_opensearch import get_query

logger = logging.getLogger(__name__)


def _default_resp_params():
    return {
        "request_id": "1",
        "action": "action",
        "resource_kind": "resource",
        "policy_version": "default",
    }


def execute_query(query, opensearch_client, index_name):
    logger.info("query: %s", json.dumps(query))
    result = opensearch_client.search(index=index_name, body=query)
    hits = result.get("hits", {}).get("hits", [])
    return hits


class TestGetQuery:
    def test_always_allow(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("always-allow", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 3

    def test_always_deny(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("always-deny", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 0

    def test_equals(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("equal", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource3"}, hits)
        )

    def test_not_equals(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("ne", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource2", "resource3"}, hits)
        )

    def test_and(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("and", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert hits[0]["_source"]["name"] == "resource3"

    def test_not_and(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("nand", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource2"}, hits)
        )

    def test_or(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("or", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 3

    def test_not_or(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("nor", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 0

    def test_in(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("in", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource3"}, hits)
        )

    def test_lt(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("lt", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert hits[0]["_source"]["name"] == "resource1"

    def test_gt(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("gt", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource2", "resource3"}, hits)
        )

    def test_lte(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("lte", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource2"}, hits)
        )

    def test_gte(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("gte", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 3

    def test_relation_some(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("relation-some", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource2"}, hits)
        )

    def test_relation_none(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("relation-none", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert hits[0]["_source"]["name"] == "resource3"

    def test_relation_is(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("relation-is", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert hits[0]["_source"]["name"] == "resource1"

    def test_relation_is_not(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("relation-is-not", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource2", "resource3"}, hits)
        )


# class TestGetQueryOverrides:
#     def test_in_single_query(
#         self, cerbos_client, principal, resource_desc, opensearch_client, index_name
#     ):
#         plan_resources_filter = PlanResourcesFilter.from_dict(
#             {
#                 "kind": PlanResourcesFilterKind.CONDITIONAL,
#                 "condition": {
#                     "expression": {
#                         "operator": "in",
#                         "operands": [
#                             {"variable": "request.resource.attr.name"},
#                             {"value": "resource1"},
#                         ],
#                     },
#                 },
#             }
#         )
#         plan_resource_resp = PlanResourcesResponse(
#             filter=plan_resources_filter,
#             **_default_resp_params(),
#         )
#         query = get_query(plan_resource_resp)
#         hits = execute_query(query, opensearch_client, index_name)
#         assert len(hits) == 1
#         assert hits[0]["_source"]["name"] == "resource1"
#

#     def test_in_multiple_query(self, resource_table, conn):
#         plan_resources_filter = PlanResourcesFilter.from_dict(
#             {
#                 "kind": PlanResourcesFilterKind.CONDITIONAL,
#                 "condition": {
#                     "expression": {
#                         "operator": "in",
#                         "operands": [
#                             {"variable": "request.resource.attr.name"},
#                             {"value": ["resource1", "resource2"]},
#                         ],
#                     },
#                 },
#             }
#         )
#         plan_resource_resp = PlanResourcesResponse(
#             filter=plan_resources_filter,
#             **_default_resp_params(),
#         )
#         attr = {
#             "request.resource.attr.name": resource_table.name,
#         }
#         query = get_query(plan_resource_resp, resource_table, attr)
#         res = conn.execute(query).fetchall()
#         assert len(res) == 2
#         assert all(map(lambda x: x.name in {"resource1", "resource2"}, res))
#
#     def test_unrecognised_response_attribute(self, resource_table):
#         unknown_attribute = "request.resource.attr.foo"
#         plan_resources_filter = PlanResourcesFilter.from_dict(
#             {
#                 "kind": PlanResourcesFilterKind.CONDITIONAL,
#                 "condition": {
#                     "expression": {
#                         "operator": "eq",
#                         "operands": [
#                             {"variable": unknown_attribute},
#                             {"value": 1},
#                         ],
#                     },
#                 },
#             }
#         )
#         plan_resource_resp = PlanResourcesResponse(
#             filter=plan_resources_filter,
#             **_default_resp_params(),
#         )
#         attr = {
#             "request.resource.attr.ownedBy": resource_table.ownedBy,
#         }
#         with pytest.raises(KeyError) as exc_info:
#             get_query(plan_resource_resp, resource_table, attr)
#         assert (
#             exc_info.value.args[0]
#             == f"Attribute does not exist in the attribute column map: {unknown_attribute}"
#         )
#
#     def test_unrecognised_filter(self, resource_table):
#         unknown_op = "unknown"
#         plan_resources_filter = PlanResourcesFilter.from_dict(
#             {
#                 "kind": PlanResourcesFilterKind.CONDITIONAL,
#                 "condition": {
#                     "expression": {
#                         "operator": unknown_op,
#                         "operands": [
#                             {"variable": "request.resource.attr.ownedBy"},
#                             {"value": "1"},
#                         ],
#                     },
#                 },
#             }
#         )
#         plan_resource_resp = PlanResourcesResponse(
#             filter=plan_resources_filter,
#             **_default_resp_params(),
#         )
#         attr = {
#             "request.resource.attr.ownedBy": resource_table.ownedBy,
#         }
#         with pytest.raises(ValueError) as exc_info:
#             get_query(plan_resource_resp, resource_table, attr)
#         assert exc_info.value.args[0] == f"Unrecognised operator: {unknown_op}"
#
#     def test_in_equals_override(self, resource_table, conn):
#         plan_resources_filter = PlanResourcesFilter.from_dict(
#             {
#                 "kind": PlanResourcesFilterKind.CONDITIONAL,
#                 "condition": {
#                     "expression": {
#                         "operator": "in",
#                         "operands": [
#                             {"variable": "request.resource.attr.name"},
#                             {"value": "resource1"},
#                         ],
#                     },
#                 },
#             }
#         )
#         plan_resource_resp = PlanResourcesResponse(
#             filter=plan_resources_filter,
#             **_default_resp_params(),
#         )
#         attr = {
#             "request.resource.attr.name": resource_table.name,
#         }
#         operator_override_fns = {
#             "in": lambda c, v: c == v,
#         }
#         query = get_query(
#             plan_resource_resp,
#             resource_table,
#             attr,
#             operator_override_fns=operator_override_fns,
#         )
#         res = conn.execute(query).fetchall()
#         assert len(res) == 1
#         assert res[0].name == "resource1"

# def test_in_override(self, cerbos_client, principal, resource_desc, resource_table):
#     plan = cerbos_client.plan_resources("in", principal, resource_desc)
#     attr = {
#         "request.resource.attr.aString": resource_table.aString,
#     }
#     operator_override_fns = {
#         "in": lambda c, v: c == any_(v),
#     }
#     query = get_query(
#         plan,
#         resource_table,
#         attr,
#         operator_override_fns=operator_override_fns,
#     )
#     query = query.with_only_columns(resource_table.id)
#     assert "= ANY (" in str(query)
