"""
Integration Tests for OpenSearch and Cerbos Client

This module contains integration tests that involve setting up OpenSearch and Cerbos
containers and testing their interactions. These tests are designed to run against
actual containerized instances of the services to validate the entire system's behavior
from an integration standpoint.

Note: These tests require Docker to be running and may take longer than unit tests
due to the complexity of setting up and tearing down containers.
"""

import logging
import os
import random
import string
import time
from contextlib import contextmanager
from typing import Generator

import backoff
import pytest
from cerbos.engine.v1 import engine_pb2
from cerbos.sdk.client import CerbosClient
from cerbos.sdk.container import CerbosContainer
from cerbos.sdk.grpc.client import CerbosClient as GrpcCerbosClient
from cerbos.sdk.model import Principal, ResourceDesc
from docker import DockerClient
from opensearchpy import OpenSearch
from opensearchpy.connection.connections import create_connection
from opensearchpy.helpers import bulk

USER_ROLE = "USER"
logger = logging.getLogger(__name__)


@contextmanager
def opensearch_container_host() -> Generator[str, None, None]:
    random_suffix = "".join(random.choices(string.ascii_lowercase, k=6))
    container_name = f"cerbos-opensearch-test-{random_suffix}"
    env = {
        "node.name": "opensearch-test",
        "cluster.name": "opensearch-docker-cluster",
        "discovery.type": "single-node",
        "bootstrap.memory_lock": "true",
        "OPENSEARCH_JAVA_OPTS": "-Xms512m -Xmx512m",
        "DISABLE_SECURITY_PLUGIN": "true",
    }

    # Start the container
    docker_client = DockerClient()
    container = docker_client.containers.run(
        image="opensearchproject/opensearch:2.8.0",
        name=container_name,
        ports={"9200/tcp": None},
        environment=env,
        detach=True,
    )

    # Get the dynamically allocated port
    port = docker_client.api.inspect_container(container.id)["NetworkSettings"][
        "Ports"
    ]["9200/tcp"][0]["HostPort"]

    yield f"localhost:{port}"

    container.remove(force=True)


@backoff.on_exception(
    backoff.expo,
    RuntimeError,
    max_tries=30,
    max_time=120,
    base=2,
)
def wait_for_opensearch_to_be_ready(client):
    if not client.ping():
        # throwing an exception here just to get backoff to retry.
        raise RuntimeError("OpenSearch is not ready yet")

    response = client.cluster.health()
    if response["status"] != "green":
        raise RuntimeError("OpenSearch cluster is not in a healthy state")


@pytest.fixture(scope="module")
def opensearch_client():
    with opensearch_container_host() as host:
        client = OpenSearch(connections=create_connection, hosts=[host])
        wait_for_opensearch_to_be_ready(client)
        logger.info("Ping succeeded, yielding client")
        yield client
        if client is not None:
            client.close()


@pytest.fixture(scope="module")
def index_name(opensearch_client):
    index_name = f"test_index_{int(time.time())}"
    index_mapping = {
        "mappings": {
            "properties": {
                "name": {"type": "text"},
                "aBool": {"type": "boolean"},
                "aString": {"type": "text"},
                "aNumber": {"type": "integer"},
                "ownedBy": {"type": "keyword"},
                "createdBy": {"type": "keyword"},
            }
        }
    }

    opensearch_client.indices.create(index=index_name, body=index_mapping)

    records = [
        {
            "_id": 1,
            "_index": index_name,
            "_source": {
                "name": "resource1",
                "aBool": True,
                "aString": "string",
                "aNumber": 1,
                "ownedBy": "1",
                "createdBy": "1",
            },
        },
        {
            "_id": 2,
            "_index": index_name,
            "_source": {
                "name": "resource2",
                "aBool": False,
                "aString": "amIAString?",
                "aNumber": 2,
                "ownedBy": "1",
                "createdBy": "2",
            },
        },
        {
            "_id": 3,
            "_index": index_name,
            "_source": {
                "name": "resource3",
                "aBool": True,
                "aString": "anotherString",
                "aNumber": 3,
                "ownedBy": "2",
                "createdBy": "2",
            },
        },
    ]

    # Use the Elasticsearch Bulk API to insert the records in a single request
    bulk(opensearch_client, records)

    # Refresh the index to make the data available for searching
    opensearch_client.indices.refresh(index=index_name)

    yield index_name

    opensearch_client.indices.delete(index=index_name, ignore=[400, 404])


@contextmanager
def cerbos_container_host(client_type: str) -> Generator[str, None, None]:
    policy_dir = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "../..", "policies")
    )

    container = CerbosContainer(image="ghcr.io/cerbos/cerbos:dev")
    container.with_volume_mapping(policy_dir, "/policies")
    container.with_env("CERBOS_NO_TELEMETRY", "1")
    container.with_command("server --set=schema.enforcement=reject")
    container.start()
    container.wait_until_ready()

    yield container.http_host() if client_type == "http" else container.grpc_host()

    container.stop()


@pytest.fixture(scope="module", params=["http", "grpc"])
def cerbos_client(request):
    client_type = request.param
    with cerbos_container_host(client_type) as host:
        client_cls = CerbosClient if client_type == "http" else GrpcCerbosClient
        with client_cls(host, tls_verify=False) as client:
            yield client


@pytest.fixture
def principal(cerbos_client):
    principal_cls = (
        engine_pb2.Principal
        if isinstance(cerbos_client, GrpcCerbosClient)
        else Principal
    )
    return principal_cls(id="1", roles={USER_ROLE})


@pytest.fixture
def resource_desc(cerbos_client):
    desc_cls = (
        engine_pb2.PlanResourcesInput.Resource
        if isinstance(cerbos_client, GrpcCerbosClient)
        else ResourceDesc
    )
    return desc_cls(kind="resource")
