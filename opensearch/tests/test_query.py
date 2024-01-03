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

    def test_intersect(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources("hasIntersection", principal, resource_desc)
        query = get_query(plan)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert all(map(lambda x: x["_source"]["name"] in {"resource1"}, hits))

    def test_intersect_multiple(
        self, cerbos_client, principal, resource_desc, opensearch_client, index_name
    ):
        plan = cerbos_client.plan_resources(
            "hasIntersectionMultiple", principal, resource_desc
        )
        query = get_query(plan)
        print(query)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource3"}, hits)
        )


class TestGetQueryOverrides:
    def test_in_single_query(
        self,
        cerbos_client,
        principal,
        resource_desc,
        opensearch_client,
        index_name,
    ):
        plan_resources_filter = PlanResourcesFilter.from_dict(
            {
                "kind": PlanResourcesFilterKind.CONDITIONAL,
                "condition": {
                    "expression": {
                        "operator": "in",
                        "operands": [
                            {"variable": "request.resource.attr.name"},
                            {"value": "resource1"},
                        ],
                    },
                },
            }
        )
        plan_resource_resp = PlanResourcesResponse(
            filter=plan_resources_filter,
            **_default_resp_params(),
        )
        query = get_query(plan_resource_resp)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 1
        assert hits[0]["_source"]["name"] == "resource1"

    def test_in_multiple_query(
        self,
        cerbos_client,
        principal,
        resource_desc,
        opensearch_client,
        index_name,
    ):
        plan_resources_filter = PlanResourcesFilter.from_dict(
            {
                "kind": PlanResourcesFilterKind.CONDITIONAL,
                "condition": {
                    "expression": {
                        "operator": "in",
                        "operands": [
                            {"variable": "request.resource.attr.name"},
                            {"value": ["resource1", "resource2"]},
                        ],
                    },
                },
            }
        )
        plan_resource_resp = PlanResourcesResponse(
            filter=plan_resources_filter,
            **_default_resp_params(),
        )
        query = get_query(plan_resource_resp)
        hits = execute_query(query, opensearch_client, index_name)
        assert len(hits) == 2
        assert all(
            map(lambda x: x["_source"]["name"] in {"resource1", "resource2"}, hits)
        )

    def test_unrecognised_filter(self):
        unknown_op = "unknown"
        plan_resources_filter = PlanResourcesFilter.from_dict(
            {
                "kind": PlanResourcesFilterKind.CONDITIONAL,
                "condition": {
                    "expression": {
                        "operator": unknown_op,
                        "operands": [
                            {"variable": "request.resource.attr.ownedBy"},
                            {"value": "1"},
                        ],
                    },
                },
            }
        )
        plan_resource_resp = PlanResourcesResponse(
            filter=plan_resources_filter,
            **_default_resp_params(),
        )
        with pytest.raises(ValueError) as exc_info:
            get_query(plan_resource_resp)
        assert exc_info.value.args[0] == f"Unsupported operator: {unknown_op}"
