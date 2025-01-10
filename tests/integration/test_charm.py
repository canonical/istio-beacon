#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import httpx
import pytest
import sh
import yaml
from helpers import validate_labels, validate_policy_exists
from pytest_operator.plugin import OpsTest
from tenacity import (
    retry,
    stop_after_delay,
    wait_exponential,
)

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
resources = {
    "metrics-proxy-image": METADATA["resources"]["metrics-proxy-image"]["upstream-source"],
}


@dataclass
class CharmDeploymentConfiguration:
    entity_url: str  # aka charm name or local path to charm
    application_name: str
    channel: str
    trust: bool
    config: Optional[dict] = None


ISTIO_K8S = CharmDeploymentConfiguration(
    entity_url="istio-k8s", application_name="istio-k8s", channel="latest/edge", trust=True
)


@pytest.mark.abort_on_fail
async def test_deploy_dependencies(ops_test: OpsTest):
    # Not the model name just an alias
    await ops_test.track_model("istio-system")
    istio_system_model = ops_test.models.get("istio-system")

    await istio_system_model.model.deploy(**asdict(ISTIO_K8S))
    await istio_system_model.model.wait_for_idle(
        [ISTIO_K8S.application_name], status="active", timeout=1000
    )


@pytest.mark.abort_on_fail
async def test_deployment(ops_test: OpsTest, istio_beacon_charm):
    await ops_test.model.deploy(
        istio_beacon_charm, resources=resources, application_name=APP_NAME, trust=True
    )
    await ops_test.model.wait_for_idle([APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_mesh_config(ops_test: OpsTest):
    await ops_test.model.applications[APP_NAME].set_config({"model-on-mesh": "true"})
    await ops_test.model.wait_for_idle(
        [APP_NAME], status="active", timeout=1000, raise_on_error=False
    )
    await validate_labels(ops_test, APP_NAME, should_be_present=True)
    validate_policy_exists(ops_test, f"allow-traffic-to-{ops_test.model.name}-modeloperator")

    await ops_test.model.applications[APP_NAME].set_config({"model-on-mesh": "false"})
    await ops_test.model.wait_for_idle(
        [APP_NAME], status="active", timeout=1000, raise_on_error=False
    )
    await validate_labels(ops_test, APP_NAME, should_be_present=False)
    with pytest.raises(httpx.HTTPStatusError):
        validate_policy_exists(ops_test, f"allow-traffic-to-{ops_test.model.name}-modeloperator")


@pytest.mark.abort_on_fail
async def test_service_mesh_relation(ops_test: OpsTest, service_mesh_tester):
    # Ensure model is on mesh
    await ops_test.model.applications[APP_NAME].set_config({"model-on-mesh": "true"})
    time.sleep(5)  # Wait for the model to be on mesh

    # Deploy tester charms
    resources = {"echo-server-image": "jmalloc/echo-server:v0.3.7"}
    # Applications that will be given authorization policies
    # receiver1 require trust because the service-mesh library interacts with k8s objects.
    await ops_test.model.deploy(
        service_mesh_tester, application_name="receiver1", resources=resources, trust=True
    )
    await ops_test.model.deploy(
        service_mesh_tester, application_name="sender1", resources=resources, trust=True
    )
    await ops_test.model.deploy(
        service_mesh_tester, application_name="sender2", resources=resources, trust=True
    )
    await ops_test.model.add_relation("receiver1:service-mesh", APP_NAME)
    await ops_test.model.add_relation("receiver1:inbound", "sender1:outbound")

    await ops_test.model.wait_for_idle([APP_NAME, "receiver1", "sender1", "sender2"])

    # Assert that communication is correctly controlled
    # sender/0 can talk to receiver on any combination of:
    # * port: [8080, 8081]
    # * path: [/foo, /bar/]
    # * method: [GET, POST]
    # but not others
    assert_request_returns_http_code(
        ops_test.model.name, "sender1/0", "http://receiver1:8080/foo", code=200
    )
    assert_request_returns_http_code(
        ops_test.model.name, "sender1/0", "http://receiver1:8081/foo", code=200
    )
    assert_request_returns_http_code(
        ops_test.model.name, "sender1/0", "http://receiver1:8080/bar/", code=200
    )
    assert_request_returns_http_code(
        ops_test.model.name, "sender1/0", "http://receiver1:8080/foo", method="post", code=200
    )
    assert_request_returns_http_code(
        ops_test.model.name, "sender1/0", "http://receiver1:8080/foo", method="delete", code=403
    )

    # other service accounts should get a 403 error
    assert_request_returns_http_code(
        ops_test.model.name, "sender2/0", "http://receiver1:8080/foo", code=403
    )


@retry(
    wait=wait_exponential(multiplier=1, min=1, max=10), stop=stop_after_delay(120), reraise=True
)
def assert_request_returns_http_code(
    model: str, source_unit: str, target_url: str, method: str = "get", code: int = 200
):
    """Get the status code for a request from a source unit to a target URL on a given method.

    Note that if the request fails (ex: python script raises an exception) the exit code will be returned.
    """
    logger.info(f"Checking {source_unit} -> {target_url} on {method}")
    try:
        resp = sh.juju.ssh(
            "-m",
            model,
            source_unit,
            f'python3 -c "import requests; resp = requests.{method}(\\"{target_url}\\"); print(resp.status_code)"',
            _return_cmd=True,
        )
        returned_code = int(str(resp).strip())
    except sh.ErrorReturnCode as e:
        logger.warning(f"Got exit code {e.exit_code} executing sh.juju.ssh")
        logger.warning(f"STDOUT: {e.stdout}")
        logger.warning(f"STDERR: {e.stderr}")
        returned_code = e.exit_code

    logger.info(
        f"Got {returned_code} for {source_unit} -> {target_url} on {method} - expected {code}"
    )

    assert returned_code == code, (
        f"Expected {code} but got {returned_code} for {source_unit} -> {target_url} on {method}"
    )
