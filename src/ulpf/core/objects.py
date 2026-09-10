"""OCSF v1.3 shared object models.

These Pydantic models represent the reusable objects referenced by multiple
OCSF event classes (Metadata, Product, Fingerprint, NetworkEndpoint, etc.).

Design decisions:
- ``model_config = ConfigDict(strict=True)`` on leaf objects to catch type
  coercion bugs early — a string ``"443"`` must not silently become int 443
  in a validated port field.
- Optional fields default to ``None`` rather than being omitted, so JSON
  serialization always reflects the full schema shape for consumers.
- Object composition mirrors the OCSF object hierarchy exactly; we do not
  flatten nested objects for "convenience" because that would violate the
  OCSF contract and break interoperability with downstream SIEM consumers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from ulpf.core.enums import FingerprintAlgorithmId  # noqa: TC001


class Product(BaseModel):
    """Identifies the data source product that generated the original event.

    Required inside ``Metadata``. Consumers use this to route events
    to vendor-specific dashboards and correlation rules.
    """

    model_config = ConfigDict(strict=True)

    name: str
    vendor_name: str
    version: str | None = None
    uid: str | None = None


class Metadata(BaseModel):
    """Event metadata describing the producer, schema version, and processing.

    ``version`` is pinned to ``"1.3.0"`` by default to ensure every event
    emitted by ULPF declares its OCSF schema version for downstream consumers.
    """

    model_config = ConfigDict(strict=True)

    version: str = "1.3.0"
    product: Product
    logged_time: int | None = None
    processed_time: int | None = None
    original_time: str | None = None
    profiles: list[str] | None = None
    uid: str | None = None


class Fingerprint(BaseModel):
    """Cryptographic hash of content, used for integrity verification.

    In the ULPF forensic envelope, this carries the SHA-256 hash of the
    original ``raw_data`` bytes to maintain chain of custody (§2).
    """

    model_config = ConfigDict(strict=True)

    algorithm: str | None = None
    algorithm_id: FingerprintAlgorithmId
    value: str


class NetworkEndpoint(BaseModel):
    """An addressable network endpoint (source or destination).

    Used by both Authentication and NetworkActivity events to describe
    where traffic originated and where it was directed.
    """

    model_config = ConfigDict(strict=True)

    ip: str | None = None
    port: int | None = None
    hostname: str | None = None
    mac: str | None = None
    name: str | None = None
    uid: str | None = None


class User(BaseModel):
    """A user identity associated with an event.

    Captures the principal that initiated or was affected by the event.
    ``type_id`` normalizes user types across vendors (e.g., 1=User, 2=Admin).
    """

    model_config = ConfigDict(strict=True)

    name: str | None = None
    uid: str | None = None
    type: str | None = None
    type_id: int | None = None
    domain: str | None = None


class OS(BaseModel):
    """Operating system information for a device.

    Populated when the log source provides host OS metadata, enabling
    OS-specific correlation rules in the downstream SIEM.
    """

    model_config = ConfigDict(strict=True)

    name: str
    type: str | None = None
    type_id: int | None = None
    version: str | None = None


class Process(BaseModel):
    """A process on a device, used in Actor and logon_process contexts.

    Identifies the trusted process that validated authentication credentials
    or the process context in which the event occurred.
    """

    model_config = ConfigDict(strict=True)

    name: str | None = None
    pid: int | None = None
    uid: str | None = None


class Session(BaseModel):
    """A user or system session.

    Tracks session lifecycle for authentication events. ``is_remote``
    distinguishes local vs. remote sessions, a key SOC triage indicator.
    """

    model_config = ConfigDict(strict=True)

    uid: str | None = None
    created_time: int | None = None
    is_remote: bool | None = None


class Actor(BaseModel):
    """The entity that initiated or caused an event.

    Aggregates user, process, and session context into a single object
    for attribution and forensic analysis.
    """

    model_config = ConfigDict(strict=True)

    user: User | None = None
    process: Process | None = None
    session: Session | None = None


class Device(BaseModel):
    """An addressable device, computer system, or host.

    Represents the endpoint where the event was detected or generated.
    """

    model_config = ConfigDict(strict=True)

    hostname: str | None = None
    ip: str | None = None
    name: str | None = None
    os: OS | None = None
    type: str | None = None
    type_id: int | None = None
    uid: str | None = None


class ConnectionInfo(BaseModel):
    """Network connection metadata.

    Captures protocol and direction information for network activity events.
    ``direction_id`` normalizes inbound/outbound/lateral distinctions.
    """

    model_config = ConfigDict(strict=True)

    protocol_name: str | None = None
    protocol_num: int | None = None
    direction_id: int | None = None
    direction: str | None = None


class Traffic(BaseModel):
    """Network traffic volume metrics.

    Byte and packet counts for network activity events. All fields are
    optional because not every log source provides complete traffic metrics.
    """

    model_config = ConfigDict(strict=True)

    bytes: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    packets: int | None = None


class Observable(BaseModel):
    """A key indicator or entity surfaced for downstream correlation.

    Each observable references an attribute path within the event
    (e.g., ``src_endpoint.ip``) along with its type and value, enabling
    IOC extraction without parsing the full event structure.
    """

    model_config = ConfigDict(strict=True)

    name: str
    type: str | None = None
    type_id: int
    value: str | None = None


class Enrichment(BaseModel):
    """Additional context from an external data source.

    Attached to events post-normalization (e.g., GeoIP enrichment for
    IP addresses in DNS answers or authentication source endpoints).
    """

    model_config = ConfigDict(strict=True)

    name: str
    value: str
    type: str | None = None
    data: dict[str, Any] | None = None
