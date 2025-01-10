#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from lightkube.core.client import Client
from lightkube.generic_resource import create_namespaced_resource
from lightkube.resources.core_v1 import Namespace
from pytest_operator.plugin import OpsTest

AuthPolicy = create_namespaced_resource(
    "security.istio.io", "v1", "AuthorizationPolicy", "authorizationpolicies"
)


async def validate_labels(ops_test: OpsTest, app_name: str, should_be_present: bool):
    """Validate the presence or absence of specific labels in the namespace."""
    client = Client()

    namespace_name = ops_test.model_name
    namespace = client.get(Namespace, namespace_name)

    expected_labels = {
        "istio.io/use-waypoint": f"{app_name}-{namespace_name}-waypoint",
        "istio.io/dataplane-mode": "ambient",
        "charms.canonical.com/istio.io.waypoint.managed-by": f"{app_name}-{namespace_name}",
    }

    for label, expected_value in expected_labels.items():
        actual_value = namespace.metadata.labels.get(label)
        if should_be_present:
            assert actual_value == expected_value, f"Label {label} is missing or incorrect."
        else:
            assert actual_value is None, f"Label {label} should have been removed."


def validate_policy_exists(ops_test: OpsTest, policy_name: str):
    client = Client()
    client.get(AuthPolicy, policy_name, namespace=ops_test.model.name)
