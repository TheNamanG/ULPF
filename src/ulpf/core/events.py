"""OCSF v1.3 event class models.

These are the top-level event types that the ULPF pipeline emits after
normalizing raw log data. Each event class:
- Extends ``BaseEvent`` with class-specific required/recommended fields.
- Carries the forensic envelope (``raw_data``, ``raw_data_hash``) per §2.
- Uses ``computed_field`` for ``type_uid`` (class_uid * 100 + activity_id).

The ``unmapped`` dict preserves any source fields that don't have a
corresponding OCSF mapping, ensuring no data is silently dropped even
when parsers are incomplete.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, computed_field

from ulpf.core.enums import (
    AuthActivityId,
    CategoryUid,
    NetworkActivityId,
    SeverityId,
    StatusId,
)
from ulpf.core.objects import (  # noqa: TC001
    Actor,
    ConnectionInfo,
    Device,
    Enrichment,
    Fingerprint,
    Metadata,
    NetworkEndpoint,
    Observable,
    Traffic,
    User,
)


class BaseEvent(BaseModel):
    """OCSF v1.3 Base Event (class_uid=0, category_uid=0).

    The generic event class that all other event classes extend.
    Can also be used directly for log formats that don't map to a
    more specific class (e.g., the RFC5424 fallback parser).

    The forensic envelope fields ``raw_data`` and ``raw_data_hash``
    satisfy both OCSF compliance and our lossless requirement (§2).
    """

    model_config = ConfigDict(strict=True, populate_by_name=True)

    # ── Classification (Required) ────────────────────────────────────────
    activity_id: int
    category_uid: int = CategoryUid.UNCATEGORIZED
    class_uid: int = 0
    severity_id: SeverityId = SeverityId.INFORMATIONAL

    # ── Occurrence (Required) ────────────────────────────────────────────
    time: int
    """Event timestamp as Unix epoch milliseconds."""

    # ── Context (Required) ───────────────────────────────────────────────
    metadata: Metadata

    # ── Primary (Recommended) ────────────────────────────────────────────
    message: str | None = None
    status_id: StatusId | None = None
    status: str | None = None
    status_code: str | None = None
    status_detail: str | None = None
    observables: list[Observable] | None = None

    # ── Context (Optional) ───────────────────────────────────────────────
    raw_data: str | None = None
    """The original log line/payload before normalization. Forensic evidence."""
    raw_data_hash: Fingerprint | None = None
    """SHA-256 fingerprint of ``raw_data`` for integrity verification and dedup."""
    raw_data_size: int | None = None
    enrichments: list[Enrichment] | None = None

    # ── Occurrence (Optional) ────────────────────────────────────────────
    count: int | None = None
    duration: int | None = None
    start_time: int | None = None
    end_time: int | None = None

    # ── Extension ────────────────────────────────────────────────────────
    unmapped: dict[str, Any] | None = None
    """Preserves source fields with no OCSF mapping. Never silently drop data."""

    # ── Computed ─────────────────────────────────────────────────────────
    @computed_field  # type: ignore[prop-decorator]
    @property
    def type_uid(self) -> int:
        """Unique identifier combining class and activity: class_uid * 100 + activity_id."""
        return self.class_uid * 100 + self.activity_id

    # ── Forensic Envelope Convenience Properties ─────────────────────────
    @property
    def raw_payload(self) -> str | None:
        """Alias for ``raw_data`` — the original log payload (§2).

        Provides ergonomic access in pipeline code without breaking
        OCSF field naming.
        """
        return self.raw_data

    @property
    def raw_sha256(self) -> str | None:
        """Extract the SHA-256 hex digest from the forensic fingerprint.

        Returns ``None`` if no fingerprint is attached.
        """
        if self.raw_data_hash is not None:
            return self.raw_data_hash.value
        return None


class Authentication(BaseEvent):
    """OCSF v1.3 Authentication event (class_uid=3002, category_uid=3).

    Reports authentication session activities: logon, logoff, ticket
    requests, and preauthentication. Used by the Linux sshd parser
    and any other authentication-focused log sources.
    """

    # Override base classification with fixed values
    class_uid: int = 3002
    category_uid: int = CategoryUid.IAM
    activity_id: AuthActivityId = AuthActivityId.UNKNOWN

    # ── Authentication-specific fields ───────────────────────────────────
    auth_protocol_id: int | None = None
    auth_protocol: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    src_endpoint: NetworkEndpoint | None = None
    logon_type_id: int | None = None
    logon_type: str | None = None
    is_mfa: bool | None = None
    is_remote: bool | None = None
    is_cleartext: bool | None = None
    is_new_logon: bool | None = None
    user: User | None = None
    actor: Actor | None = None
    device: Device | None = None
    service: str | None = None


class NetworkActivity(BaseEvent):
    """OCSF v1.3 Network Activity event (class_uid=4001, category_uid=4).

    Represents network connections, flows, and protocol-specific data.
    Used by the Cisco ASA parser and similar perimeter device log sources.
    """

    # Override base classification with fixed values
    class_uid: int = 4001
    category_uid: int = CategoryUid.NETWORK_ACTIVITY
    activity_id: NetworkActivityId = NetworkActivityId.UNKNOWN

    # ── Network-specific fields ──────────────────────────────────────────
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    connection_info: ConnectionInfo | None = None
    traffic: Traffic | None = None
    device: Device | None = None
    app_name: str | None = None
