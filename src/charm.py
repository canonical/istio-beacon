#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Istio Beacon Charm."""

import hashlib
import logging
import time
from typing import Dict, List

import ops
import pydantic
from charms.istio_beacon_k8s.v0.service_mesh import MeshPolicy, ServiceMeshProvider
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Namespace
from lightkube_extensions.batch import KubernetesResourceManager, create_charm_default_labels
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from ops.pebble import ChangeError, Layer

from models import (
    AllowedRoutes,
    AuthorizationPolicySpec,
    From,
    IstioWaypointResource,
    IstioWaypointSpec,
    Listener,
    Metadata,
    Operation,
    PolicyTargetReference,
    Rule,
    Source,
    To,
    WorkloadSelector,
)

logger = logging.getLogger(__name__)

RESOURCE_TYPES = {
    "Gateway": create_namespaced_resource(
        "gateway.networking.k8s.io", "v1", "Gateway", "gateways"
    ),
    "AuthorizationPolicy": create_namespaced_resource(
        "security.istio.io",
        "v1",
        "AuthorizationPolicy",
        "authorizationpolicies",
    ),
}

AUTHORIZATION_POLICY_LABEL = "istio-authorization-policy"
AUTHORIZATION_POLICY_RESOURCE_TYPES = {RESOURCE_TYPES["AuthorizationPolicy"]}
WAYPOINT_LABEL = "istio-waypoint"
WAYPOINT_RESOURCE_TYPES = {RESOURCE_TYPES["Gateway"]}


@trace_charm(
    tracing_endpoint="_charm_tracing_endpoint",
    # we don't add a cert because istio does TLS his way
    # TODO: fix this when https://github.com/canonical/istio-beacon-k8s-operator/issues/33 is closed
    extra_types=[ServiceMeshProvider, MetricsEndpointProvider],
)
class IstioBeaconCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self._lightkube_field_manager: str = self.app.name
        self._lightkube_client = None
        self._app_identity = f"{self.app.name}-{self.model.name}"

        self._telemetry_labels = {
            f"charms.canonical.com/{self.model.name}.{self.app.name}.telemetry": "aggregated"
        }
        # Configure Observability
        self._scraping = MetricsEndpointProvider(
            self,
            jobs=[{"static_configs": [{"targets": ["*:15090"]}]}],
        )
        self._tracing = TracingEndpointRequirer(
            self, protocols=["otlp_http"], relation_name="charm-tracing"
        )

        self._charm_tracing_endpoint = (
            self._tracing.get_endpoint("otlp_http") if self._tracing.relations else None
        )

        self._waypoint_name = f"{self.app.name}-{self.model.name}-waypoint"

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.on.metrics_proxy_pebble_ready, self._metrics_proxy_pebble_ready
        )
        self._mesh = ServiceMeshProvider(self, labels=self.mesh_labels())

        self.framework.observe(self.on["service-mesh"].relation_changed, self.on_mesh_changed)
        self.framework.observe(self.on["service-mesh"].relation_broken, self.on_mesh_broken)

    def _setup_proxy_pebble_service(self):
        """Define and start the metrics broadcast proxy Pebble service."""
        proxy_container = self.unit.get_container("metrics-proxy")
        if not proxy_container.can_connect():
            return
        proxy_layer = Layer(
            {
                "summary": "Metrics Broadcast Proxy Layer",
                "description": "Pebble layer for the metrics broadcast proxy",
                "services": {
                    "metrics-proxy": {
                        "override": "replace",
                        "summary": "Metrics Broadcast Proxy",
                        "command": f"metrics-proxy --labels {self.format_labels(self._telemetry_labels)}",
                        "startup": "enabled",
                    }
                },
            }
        )

        proxy_container.add_layer("metrics-proxy", proxy_layer, combine=True)

        try:
            proxy_container.replan()
        except ChangeError as e:
            logger.error(f"Error while replanning proxy container: {e}")

    def _on_config_changed(self, _):
        """Event handler for config changed."""
        self._sync_all_resources()

    def _metrics_proxy_pebble_ready(self, _):
        """Event handler for metrics_proxy_pebble_ready."""
        self._sync_all_resources()

    def on_mesh_changed(self, _):
        """Event handler for service-mesh relation_changed."""
        self._sync_all_resources()

    def on_mesh_broken(self, _):
        """Event handler for service-mesh relation_broken."""
        self._sync_all_resources()

    def _on_remove(self, _):
        """Event handler for remove."""
        self._remove_labels()
        for krm in (
            self._get_waypoint_resource_manager(),
            self._get_authorization_policy_resource_manager(),
        ):
            krm.delete()

    @property
    def lightkube_client(self):
        """Returns a lightkube client configured for this charm."""
        if self._lightkube_client is None:
            self._lightkube_client = Client(
                namespace=self.model.name, field_manager=self._lightkube_field_manager
            )
        return self._lightkube_client

    def _get_authorization_policy_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=AUTHORIZATION_POLICY_LABEL
            ),
            resource_types=AUTHORIZATION_POLICY_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _get_waypoint_resource_manager(self):
        return KubernetesResourceManager(
            labels=create_charm_default_labels(
                self.app.name, self.model.name, scope=WAYPOINT_LABEL
            ),
            resource_types=WAYPOINT_RESOURCE_TYPES,  # pyright: ignore
            lightkube_client=self.lightkube_client,
            logger=logger,
        )

    def _is_waypoint_deployment_ready(self) -> bool:
        """Check if the deployment is ready after 10 attempts."""
        timeout = int(self.config["ready-timeout"])
        check_interval = 10
        attempts = timeout // check_interval

        for _ in range(attempts):
            try:
                deployment = self.lightkube_client.get(
                    Deployment,
                    name=self._waypoint_name,
                    namespace=self.model.name,
                )
                if (
                    deployment.status
                    and deployment.status.readyReplicas == deployment.status.replicas
                ):
                    return True
                logger.info("Deployment not ready, retrying...")
            except ApiError:
                logger.info("Deployment not found, retrying...")

            time.sleep(check_interval)

        return False

    def _is_waypoint_ready(self) -> bool:
        if not self._is_waypoint_deployment_ready():
            return False
        return True

    def _sync_all_resources(self):
        if not self.unit.is_leader():
            self.unit.status = BlockedStatus("Waypoint can only be provided on the leader unit.")
            return

        self.unit.status = MaintenanceStatus("Validating waypoint readiness")
        self._sync_waypoint_resources()
        if not self._is_waypoint_ready():
            raise RuntimeError("Waypoint's k8s deployment not ready, is istio properly installed?")

        self._setup_proxy_pebble_service()

        self.unit.status = MaintenanceStatus("Updating AuthorizationPolicies")
        self._sync_authorization_policies()

        self.unit.status = ActiveStatus()

    def _build_authorization_policies(self, mesh_info: List[MeshPolicy]):
        """Build all managed authorization policies."""
        authorization_policies = [None] * len(mesh_info)
        for i, policy in enumerate(mesh_info):
            target_service = policy.target_service or policy.target_app_name
            if policy.target_service is None:
                logger.info(
                    f"Got policy for application '{policy.target_app_name}' that has no target_service. "
                    f"Defaulting to application name '{target_service}'."
                )

            authorization_policies[i] = RESOURCE_TYPES["AuthorizationPolicy"](  # type: ignore
                metadata=ObjectMeta(
                    name=self._generate_authorization_policy_name(policy),
                    # FIXME: This should be the namespace of the target app, not the beacon
                    namespace=self.model.name,
                ),
                spec=AuthorizationPolicySpec(
                    targetRefs=[
                        PolicyTargetReference(
                            kind="Service",
                            group="",
                            name=target_service,
                        )
                    ],
                    rules=[
                        Rule(
                            from_=[  # type: ignore # this is accessible via an alias
                                From(
                                    source=Source(
                                        principals=[
                                            _get_peer_identity_for_juju_application(
                                                policy.source_app_name, self.model.name
                                            )
                                        ]
                                    )
                                )
                            ],
                            to=[
                                To(
                                    operation=Operation(
                                        # TODO: Make these ports strings instead of ints in endpoint?
                                        ports=[str(p) for p in endpoint.ports]
                                        if endpoint.ports
                                        else [],
                                        hosts=endpoint.hosts,
                                        methods=endpoint.methods,
                                        paths=endpoint.paths,
                                    )
                                )
                                for endpoint in policy.endpoints
                            ],
                        )
                    ],
                    # by_alias=True because the model includes an alias for the `from` field
                    # exclude_unset=True because unset fields will be treated as their default values in Kubernetes
                    # exclude_none=True because null values in this data always mean the Kubernetes default
                ).model_dump(by_alias=True, exclude_unset=True, exclude_none=True),
            )

        # We need to allow the juju controller to be able to talk to the model operator
        if self.config["model-on-mesh"]:
            authorization_policies.append(
                RESOURCE_TYPES["AuthorizationPolicy"](  # type: ignore
                    metadata=ObjectMeta(
                        name=f"allow-traffic-to-{self.model.name}-modeloperator",
                        namespace=self.model.name,
                    ),
                    spec=AuthorizationPolicySpec(
                        selector=WorkloadSelector(
                            matchLabels={"operator.juju.is/name": "modeloperator"}
                        ),
                        rules=[Rule()],
                    ).model_dump(by_alias=True, exclude_unset=True, exclude_none=True),
                )
            )

        return authorization_policies

    def _construct_waypoint(self):
        gateway = IstioWaypointResource(
            metadata=Metadata(
                name=self._waypoint_name,
                namespace=self.model.name,
                labels={"istio.io/waypoint-for": "all", **self._telemetry_labels},
            ),
            spec=IstioWaypointSpec(
                gatewayClassName="istio-waypoint",
                listeners=[
                    Listener(
                        name="mesh",
                        port=15008,
                        protocol="HBONE",
                        allowedRoutes=AllowedRoutes(namespaces={"from": "All"}),
                    )
                ],
            ),
        )
        gateway_resource = RESOURCE_TYPES["Gateway"]
        return gateway_resource(
            metadata=ObjectMeta.from_dict(gateway.metadata.model_dump()),
            spec=gateway.spec.model_dump(),
        )

    def _sync_authorization_policies(self):
        """Sync authorization policies."""
        krm = self._get_authorization_policy_resource_manager()
        if self.config["manage-authorization-policies"]:
            authorization_policies = self._build_authorization_policies(self._mesh.mesh_info())
            logger.debug("Reconciling state of AuthorizationPolicies to:")
            logger.debug(authorization_policies)
        else:
            # We reconcile to an empty list rather than skip reconciling entirely so that, if the user changes the
            # config while the charm is running, we remove all AuthorizationPolicies.
            logger.debug(
                "AuthorizationPolicies creation is disabled - reconciling to no Authorization Policies."
            )
            authorization_policies = []
        krm.reconcile(authorization_policies)  # type: ignore

    def _sync_waypoint_resources(self):
        resources_list = []
        krm = self._get_waypoint_resource_manager()
        resource_to_append = self._construct_waypoint()
        resources_list.append(resource_to_append)
        krm.reconcile(resources_list)

        if self.config["model-on-mesh"]:
            self._add_labels()
        else:
            self._remove_labels()

    def _get_namespace(self):
        """Retrieve the namespace object."""
        try:
            return self.lightkube_client.get(Namespace, self.model.name)
        except ApiError as e:
            logger.error(f"Error fetching namespace: {e}")
            return None

    def _patch_namespace(self, namespace):
        """Patch the namespace with updated labels."""
        try:
            self.lightkube_client.patch(Namespace, self.model.name, namespace)
        except ApiError as e:
            logger.error(f"Error patching namespace: {e}")

    def _add_labels(self):
        """Add specific labels to the namespace."""
        namespace = self._get_namespace()
        if not namespace:
            raise RuntimeError(f"Error fetching namespace: {namespace}")

        # Ensure metadata is not None
        if namespace.metadata is None:
            namespace.metadata = ObjectMeta()

        # Ensure labels are a dictionary even if they are initially None or not set
        if namespace.metadata.labels is None:  # pyright: ignore
            namespace.metadata.labels = {}  # pyright: ignore

        existing_labels = namespace.metadata.labels  # pyright: ignore
        if (
            existing_labels.get("istio.io/use-waypoint")
            or existing_labels.get("istio.io/dataplane-mode")
        ) and existing_labels.get(
            "charms.canonical.com/istio.io.waypoint.managed-by"
        ) != f"{self._app_identity}":
            logger.error(
                f"Cannot add labels: Namespace '{self.model.name}' is already configured with Istio labels managed by another entity."
            )
            return

        labels_to_add = {
            "istio.io/use-waypoint": self._waypoint_name,
            "istio.io/dataplane-mode": "ambient",
            "charms.canonical.com/istio.io.waypoint.managed-by": f"{self._app_identity}",
        }

        namespace.metadata.labels.update(labels_to_add)  # pyright: ignore
        self._patch_namespace(namespace)

    def _remove_labels(self):
        """Remove specific labels from the namespace."""
        namespace = self._get_namespace()
        if not namespace:
            raise RuntimeError(f"Error fetching namespace: {namespace}")

        if namespace.metadata and namespace.metadata.labels:
            if (
                namespace.metadata.labels.get("charms.canonical.com/istio.io.waypoint.managed-by")
                != f"{self._app_identity}"
            ):
                logger.warning(
                    f"Cannot remove labels: Namespace '{self.model.name}' has Istio labels managed by another entity."
                )
                return

            labels_to_remove = {
                "istio.io/use-waypoint": None,
                "istio.io/dataplane-mode": None,
                "charms.canonical.com/istio.io.waypoint.managed-by": None,
            }

            namespace.metadata.labels.update(labels_to_remove)
            self._patch_namespace(namespace)

    def mesh_labels(self):
        """Labels required for a workload to join the mesh."""
        if self.config["model-on-mesh"]:
            return {}
        return {
            "istio.io/dataplane-mode": "ambient",
            "istio.io/use-waypoint": self._waypoint_name,
            "istio.io/use-waypoint-namespace": self.model.name,
        }

    def _generate_authorization_policy_name(self, mesh_policy: MeshPolicy) -> str:
        """Generate a unique name for an AuthorizationPolicy, suffixing a hash of the MeshPolicy to avoid collisions.

        The name has the following general format:
            {app_name}-{model_name}-policy-{source_app_name}-{source_namespace}-{target_app_name}-{hash}
        but source_app_name and target_app_name will be truncated if the total name exceeds Kubernetes's limit of 253
        characters.
        """
        # omit target_app_namespace from the name here because that will be the namespace the policy is generated in, so
        # adding it here is redundant
        name = "-".join(
            [
                self.app.name,
                self.model.name,
                "policy",
                mesh_policy.source_app_name,
                mesh_policy.source_namespace,
                mesh_policy.target_app_name,
                _hash_pydantic_model(mesh_policy)[:8],
            ]
        )
        if len(name) > 253:
            # Truncate the name to fit within Kubernetes's 253-character limit
            # juju app names and models must be <= 63 characters each and we have ~20 characters of static text, so
            # if name is too long just take the first 30 characters of source_app_name, source_namespace, and
            # target_app_name to be safe.
            name = "-".join(
                [
                    self.app.name,
                    self.model.name,
                    "policy",
                    mesh_policy.source_app_name[:30],
                    mesh_policy.source_namespace[:30],
                    mesh_policy.target_app_name[:30],
                    _hash_pydantic_model(mesh_policy)[:8],
                ]
            )
        return name

    @staticmethod
    def format_labels(label_dict: Dict[str, str]) -> str:
        """Format a dictionary into a comma-separated string of key=value pairs."""
        return ",".join(f"{key}={value}" for key, value in label_dict.items())


def _get_peer_identity_for_juju_application(app_name, namespace):
    """Return a Juju application's peer identity.

    Format returned is defined by `principals` in
    [this reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/#Source):

    This function relies on the Juju convention that each application gets a ServiceAccount of the same name in the same
    namespace.
    """
    service_account = app_name
    return _get_peer_identity_for_service_account(service_account, namespace)


def _get_peer_identity_for_service_account(service_account, namespace):
    """Return a ServiceAccount's peer identity.

    Format returned is defined by `principals` in
    [this reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/#Source):
        "cluster.local/ns/{namespace}/sa/{service_account}"
    """
    return f"cluster.local/ns/{namespace}/sa/{service_account}"


def _hash_pydantic_model(model: pydantic.BaseModel) -> str:
    """Hash a pydantic BaseModel object.

    This is a simple hashing of the json model dump of the pydantic model.  Items that are excluded from this dump will
    will not affect the output.
    """

    def _stable_hash(data):
        return hashlib.sha256(str(data).encode()).hexdigest()

    # Note: This hash will be affected by changes in how pydandic stringifies data, so if they change things our hash
    # will change too.  If that proves an issue, we could implement something more controlled here.
    return _stable_hash(model)


if __name__ == "__main__":
    ops.main(IstioBeaconCharm)  # type: ignore
