"""OCSF v1.3 enumeration types.

Each enum mirrors the normative OCSF v1.3 integer identifiers exactly.
Using ``IntEnum`` ensures JSON serialization produces the integer value
while keeping code self-documenting. The ``OTHER = 99`` sentinel is
present on every enum to handle unmapped source values per OCSF convention.
"""

from __future__ import annotations

from enum import IntEnum


class CategoryUid(IntEnum):
    """OCSF event category identifiers (v1.3).

    Every event belongs to exactly one category. The parser-definition
    schema (§4) references these to tag its output.
    """

    UNCATEGORIZED = 0
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class SeverityId(IntEnum):
    """Normalized severity identifiers.

    Smaller values = lower impact. Parsers map source-specific severity
    strings to these integer codes during normalization.
    """

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class StatusId(IntEnum):
    """Normalized event outcome status.

    Maps source outcomes to Success/Failure for consistent downstream
    correlation across heterogeneous log sources.
    """

    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class ActivityId(IntEnum):
    """Base event activity identifiers.

    Subclassed by event-specific enums (``AuthActivityId``, etc.)
    to add class-specific activity codes while preserving the
    ``UNKNOWN`` / ``OTHER`` sentinel convention.
    """

    UNKNOWN = 0
    OTHER = 99


class AuthActivityId(IntEnum):
    """Authentication event activity identifiers (class_uid=3002).

    Maps authentication-specific actions to OCSF-normalized codes.
    """

    UNKNOWN = 0
    LOGON = 1
    LOGOFF = 2
    AUTH_TICKET = 3
    SERVICE_TICKET = 4
    SERVICE_TICKET_RENEW = 5
    PREAUTH = 6
    OTHER = 99


class AuthProtocolId(IntEnum):
    """Authentication protocol identifiers.

    Used to normalize the protocol used for credential verification
    across vendors (SSH → Other/99, Kerberos → 2, etc.).
    """

    UNKNOWN = 0
    NTLM = 1
    KERBEROS = 2
    DIGEST = 3
    OPENID = 4
    SAML = 5
    OAUTH_2_0 = 6
    PAP = 7
    CHAP = 8
    EAP = 9
    RADIUS = 10
    OTHER = 99


class LogonTypeId(IntEnum):
    """Logon type identifiers for authentication events.

    Distinguishes interactive, network, batch, and service logon types
    which have different security implications in SOC analysis.
    """

    UNKNOWN = 0
    SYSTEM = 1
    INTERACTIVE = 2
    NETWORK = 3
    BATCH = 4
    OS_SERVICE = 5
    UNLOCK = 7
    NETWORK_CLEARTEXT = 8
    NEW_CREDENTIALS = 9
    REMOTE_INTERACTIVE = 10
    CACHED_INTERACTIVE = 11
    CACHED_REMOTE_INTERACTIVE = 12
    CACHED_UNLOCK = 13
    OTHER = 99


class NetworkActivityId(IntEnum):
    """Network Activity event activity identifiers (class_uid=4001).

    Maps firewall/flow actions to OCSF-normalized codes used by
    Cisco ASA, iptables, and similar perimeter devices.
    """

    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RESET = 3
    FAIL = 4
    REFUSE = 5
    TRAFFIC = 6
    OTHER = 99


class FingerprintAlgorithmId(IntEnum):
    """Hash algorithm identifiers for the OCSF Fingerprint object.

    The ULPF forensic envelope always uses SHA-256 (§2) for raw_data_hash
    to maintain chain of custody. Other algorithms are defined for
    completeness against the OCSF spec.
    """

    UNKNOWN = 0
    MD5 = 1
    SHA1 = 2
    SHA256 = 3
    SHA512 = 4
    OTHER = 99
