#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""This module defines Pydantic schemas for various resources used in the Kubernetes Gateway API."""
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# Global metadata schema
class Metadata(BaseModel):
    """Global metadata schema for Kubernetes resources."""

    name: str
    namespace: str
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None


class AllowedRoutes(BaseModel):
    """AllowedRoutes defines namespaces from which traffic is allowed."""

    namespaces: Dict[str, str]


class Listener(BaseModel):
    """Listener defines a port and protocol configuration."""

    name: str
    port: int
    protocol: str
    allowedRoutes: AllowedRoutes  # noqa: N815


class IstioWaypointSpec(BaseModel):
    """IstioWaypointSpec defines the specification of a waypoint."""

    gatewayClassName: str  # noqa: N815
    listeners: List[Listener]


class IstioWaypointResource(BaseModel):
    """IstioWaypointResource defines the structure of an waypoint Kubernetes resource."""

    metadata: Metadata
    spec: IstioWaypointSpec


class Action(str, Enum):
    """Action is a type that represents the action to take when a rule matches."""

    allow = "ALLOW"
    deny = "DENY"
    # These exist, but not sure if we've implemented everything to support them
    # audit = "AUDIT"
    # custom = "CUSTOM"


class PolicyTargetReference(BaseModel):
    """PolicyTargetReference defines the target of the policy."""
    group: str
    kind: str
    name: str
    namespace: Optional[str] = None


class WorkloadSelector(BaseModel):
    """WorkloadSelector defines the selector for the policy."""
    matchLabels: Dict[str, str]


class Source(BaseModel):
    """Source defines the source of the policy."""
    principals: Optional[List[str]] = None
    notPrincipals: Optional[List[str]] = None
    # Did not model everything.


class From(BaseModel):
    """From defines the source of the policy."""
    source: Source


class Operation(BaseModel):
    """Operation defines the operation of the To model."""
    hosts: Optional[List[str]] = None
    notHosts: Optional[List[str]] = None
    ports: Optional[List[str]] = None
    methods: Optional[List[str]] = None
    notMethods: Optional[List[str]] = None
    paths: Optional[List[str]] = None
    notPaths: Optional[List[str]] = None


class To(BaseModel):
    """To defines the destination of the policy."""
    operation: Optional[Operation] = None


class Condition(BaseModel):
    """Condition defines the condition for the rule."""
    key: str
    values: Optional[List[str]] = None
    notValues: Optional[List[str]] = None


class Rule(BaseModel):
    """Rule defines a policy rule."""
    from_: Optional[List[From]] = Field(default=None, alias="from")
    to: Optional[List[To]] = None
    when: Optional[List[Condition]] = None
    # Allows us to populate with `Rule(from_=[From()])`.  Without this, we can only use they alias `from`, which is
    # protected, meaning we could only build rules from a dict like `Rule(**{"from": [From()]})`.
    model_config = ConfigDict(populate_by_name=True)


class AuthorizationPolicySpec(BaseModel):
    """AuthorizationPolicyResource defines the structure of an Istio AuthorizationPolicy Kubernetes resource."""
    action: Action = Action.allow
    targetRefs: List[PolicyTargetReference]
    rules: List[Rule]
    # Not implemented, but it exists
    # selector: WorkloadSelector
    # provider
