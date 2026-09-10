"""Tests for OCSF v1.3 Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ulpf.core.enums import (
    AuthActivityId,
    CategoryUid,
    FingerprintAlgorithmId,
    NetworkActivityId,
    SeverityId,
    StatusId,
)
from ulpf.core.events import Authentication, BaseEvent, NetworkActivity
from ulpf.core.objects import (
    ConnectionInfo,
    Fingerprint,
    Metadata,
    NetworkEndpoint,
    Traffic,
    User,
)


class TestBaseEvent:
    """Validate BaseEvent model construction and constraints."""

    def test_minimal_valid_event(self, sample_metadata: Metadata, current_time_ms: int) -> None:
        """A BaseEvent with only required fields should validate."""
        event = BaseEvent(
            activity_id=0,
            category_uid=CategoryUid.UNCATEGORIZED,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.class_uid == 0
        assert event.category_uid == 0
        assert event.activity_id == 0

    def test_type_uid_computation(self, sample_metadata: Metadata, current_time_ms: int) -> None:
        """type_uid must equal class_uid * 100 + activity_id."""
        event = BaseEvent(
            activity_id=99,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.type_uid == 0 * 100 + 99

    def test_missing_required_field_raises(self, current_time_ms: int) -> None:
        """Omitting required 'metadata' should raise ValidationError."""
        with pytest.raises(ValidationError):
            BaseEvent(**{  # type: ignore[arg-type]
                "activity_id": 0,
                "class_uid": 0,
                "severity_id": SeverityId.INFORMATIONAL,
                "time": current_time_ms,
                # metadata is missing
            })

    def test_strict_mode_rejects_string_for_int(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """strict=True means a string '0' must not silently become int 0."""
        with pytest.raises(ValidationError):
            BaseEvent(
                activity_id="0",  # type: ignore[arg-type]
                class_uid=0,
                severity_id=SeverityId.INFORMATIONAL,
                time=current_time_ms,
                metadata=sample_metadata,
            )

    def test_raw_payload_property(self, sample_metadata: Metadata, current_time_ms: int) -> None:
        """raw_payload property should alias raw_data."""
        event = BaseEvent(
            activity_id=0,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
            raw_data="original log line",
        )
        assert event.raw_payload == "original log line"

    def test_raw_sha256_property(self, sample_metadata: Metadata, current_time_ms: int) -> None:
        """raw_sha256 should extract hash value from raw_data_hash."""
        fp = Fingerprint(
            algorithm="SHA-256",
            algorithm_id=FingerprintAlgorithmId.SHA256,
            value="abc123def456",
        )
        event = BaseEvent(
            activity_id=0,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
            raw_data_hash=fp,
        )
        assert event.raw_sha256 == "abc123def456"

    def test_raw_sha256_none_when_no_hash(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """raw_sha256 should return None when no fingerprint is attached."""
        event = BaseEvent(
            activity_id=0,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.raw_sha256 is None

    def test_unmapped_preserves_extra_fields(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """unmapped dict should preserve arbitrary key-value pairs."""
        event = BaseEvent(
            activity_id=0,
            class_uid=0,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
            unmapped={"facility": 16, "hostname": "myhost"},
        )
        assert event.unmapped == {"facility": 16, "hostname": "myhost"}


class TestAuthentication:
    """Validate Authentication event model."""

    def test_authentication_class_uid(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """Authentication events must have class_uid=3002, category_uid=3."""
        event = Authentication(
            activity_id=AuthActivityId.LOGON,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.class_uid == 3002
        assert event.category_uid == CategoryUid.IAM

    def test_authentication_type_uid(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """type_uid for auth logon: 3002 * 100 + 1 = 300201."""
        event = Authentication(
            activity_id=AuthActivityId.LOGON,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.type_uid == 300201

    def test_full_authentication_event(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """Construct a fully-populated Authentication event."""
        event = Authentication(
            activity_id=AuthActivityId.LOGON,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
            status_id=StatusId.SUCCESS,
            status="Success",
            user=User(name="admin"),
            src_endpoint=NetworkEndpoint(ip="192.168.1.100", port=52413),
            dst_endpoint=NetworkEndpoint(hostname="webserver"),
            auth_protocol="SSH",
            auth_protocol_id=99,
            is_remote=True,
            is_mfa=False,
            logon_type_id=3,
            logon_type="Network",
            service="sshd",
        )
        assert event.user is not None
        assert event.user.name == "admin"
        assert event.src_endpoint is not None
        assert event.src_endpoint.ip == "192.168.1.100"
        assert event.is_remote is True


class TestNetworkActivity:
    """Validate NetworkActivity event model."""

    def test_network_activity_class_uid(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """NetworkActivity events must have class_uid=4001, category_uid=4."""
        event = NetworkActivity(
            activity_id=NetworkActivityId.OPEN,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.class_uid == 4001
        assert event.category_uid == CategoryUid.NETWORK_ACTIVITY

    def test_network_activity_type_uid(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """type_uid for network open: 4001 * 100 + 1 = 400101."""
        event = NetworkActivity(
            activity_id=NetworkActivityId.OPEN,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
        )
        assert event.type_uid == 400101

    def test_full_network_activity_event(
        self, sample_metadata: Metadata, current_time_ms: int
    ) -> None:
        """Construct a fully-populated NetworkActivity event."""
        event = NetworkActivity(
            activity_id=NetworkActivityId.OPEN,
            severity_id=SeverityId.INFORMATIONAL,
            time=current_time_ms,
            metadata=sample_metadata,
            src_endpoint=NetworkEndpoint(ip="10.0.0.1", port=1234),
            dst_endpoint=NetworkEndpoint(ip="192.168.1.1", port=443),
            connection_info=ConnectionInfo(
                protocol_name="TCP",
                protocol_num=6,
                direction_id=1,
                direction="Inbound",
            ),
            traffic=Traffic(bytes=4567),
        )
        assert event.src_endpoint is not None
        assert event.src_endpoint.ip == "10.0.0.1"
        assert event.traffic is not None
        assert event.traffic.bytes == 4567
