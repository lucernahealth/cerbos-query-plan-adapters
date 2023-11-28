from types import MappingProxyType
from typing import Any, Callable

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


def get_query(
    query_plan: PlanResourcesResponse | response_pb2.PlanResourcesResponse,
) -> Any:
    return {"query": {"match_all": {}}}
