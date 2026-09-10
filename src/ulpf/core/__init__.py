"""OCSF v1.3 core models and data contracts.

All Pydantic models in this package are pinned to OCSF v1.3 (§4).
They serve as the single source of truth for what constitutes a valid,
normalized event in the ULPF pipeline.
"""

from ulpf.core.enums import (
    ActivityId,
    AuthActivityId,
    AuthProtocolId,
    CategoryUid,
    FingerprintAlgorithmId,
    LogonTypeId,
    NetworkActivityId,
    SeverityId,
    StatusId,
)
from ulpf.core.events import Authentication, BaseEvent, NetworkActivity
from ulpf.core.forensic import build_fingerprint, compute_raw_sha256, wrap_forensic_envelope
from ulpf.core.objects import (
    OS,
    Actor,
    ConnectionInfo,
    Device,
    Enrichment,
    Fingerprint,
    Metadata,
    NetworkEndpoint,
    Observable,
    Process,
    Product,
    Session,
    Traffic,
    User,
)

__all__ = [
    "OS",
    # Enums
    "ActivityId",
    # Objects
    "Actor",
    "AuthActivityId",
    "AuthProtocolId",
    # Events
    "Authentication",
    "BaseEvent",
    "CategoryUid",
    "ConnectionInfo",
    "Device",
    "Enrichment",
    "Fingerprint",
    "FingerprintAlgorithmId",
    "LogonTypeId",
    "Metadata",
    "NetworkActivity",
    "NetworkActivityId",
    "NetworkEndpoint",
    "Observable",
    "Process",
    "Product",
    "Session",
    "SeverityId",
    "StatusId",
    "Traffic",
    "User",
    # Forensic
    "build_fingerprint",
    "compute_raw_sha256",
    "wrap_forensic_envelope",
]
