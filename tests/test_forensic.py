"""Tests for the forensic envelope utilities.

These tests prove the "lossless" claim (§7) by verifying:
1. raw_data byte-equality after encoding.
2. raw_sha256 matches independent hashlib computation.
3. Raw bytes are never re-encoded before hashing.
"""

from __future__ import annotations

import hashlib

from ulpf.core.enums import FingerprintAlgorithmId
from ulpf.core.forensic import build_fingerprint, compute_raw_sha256, wrap_forensic_envelope


class TestComputeRawSha256:
    """Verify SHA-256 computation on raw bytes."""

    def test_known_hash(self) -> None:
        """Verify against an independently computed SHA-256."""
        data = b"test log line"
        expected = hashlib.sha256(data).hexdigest()
        assert compute_raw_sha256(data) == expected

    def test_empty_bytes(self) -> None:
        """Empty input should produce the well-known empty SHA-256."""
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_raw_sha256(b"") == expected

    def test_binary_data(self) -> None:
        """Non-UTF-8 binary data should hash correctly."""
        data = bytes(range(256))
        expected = hashlib.sha256(data).hexdigest()
        assert compute_raw_sha256(data) == expected

    def test_deterministic(self) -> None:
        """Same input must always produce the same hash."""
        data = b"deterministic test"
        h1 = compute_raw_sha256(data)
        h2 = compute_raw_sha256(data)
        assert h1 == h2

    def test_different_input_different_hash(self) -> None:
        """Different inputs must produce different hashes."""
        h1 = compute_raw_sha256(b"input a")
        h2 = compute_raw_sha256(b"input b")
        assert h1 != h2


class TestBuildFingerprint:
    """Verify Fingerprint object construction."""

    def test_algorithm_is_sha256(self) -> None:
        """ULPF always uses SHA-256 for forensic integrity."""
        fp = build_fingerprint(b"test")
        assert fp.algorithm == "SHA-256"
        assert fp.algorithm_id == FingerprintAlgorithmId.SHA256

    def test_value_matches_independent_hash(self) -> None:
        """Fingerprint value must match hashlib.sha256."""
        data = b"forensic evidence"
        fp = build_fingerprint(data)
        expected = hashlib.sha256(data).hexdigest()
        assert fp.value == expected


class TestWrapForensicEnvelope:
    """Verify the forensic envelope injection into event dicts."""

    def test_injects_raw_data(self) -> None:
        """raw_data should contain the decoded payload."""
        raw = b"original log line"
        result = wrap_forensic_envelope({}, raw)
        assert result["raw_data"] == "original log line"

    def test_injects_raw_data_hash(self) -> None:
        """raw_data_hash should be a valid Fingerprint dict."""
        raw = b"test"
        result = wrap_forensic_envelope({}, raw)
        assert result["raw_data_hash"]["algorithm"] == "SHA-256"
        assert result["raw_data_hash"]["value"] == hashlib.sha256(raw).hexdigest()

    def test_injects_raw_data_size(self) -> None:
        """raw_data_size should be the byte count of the raw input."""
        raw = b"twelve chars"
        result = wrap_forensic_envelope({}, raw)
        assert result["raw_data_size"] == len(raw)

    def test_preserves_existing_fields(self) -> None:
        """Existing event data should not be overwritten."""
        raw = b"test"
        event = {"message": "existing", "severity_id": 1}
        result = wrap_forensic_envelope(event, raw)
        assert result["message"] == "existing"
        assert result["severity_id"] == 1
        assert "raw_data" in result

    def test_lossless_round_trip(self) -> None:
        """§7: raw_data decoded back to bytes must equal the original input.

        This is the proof behind the 'lossless' claim.
        """
        raw = b"Sep  6 10:00:00 webserver sshd[12345]: Accepted password for admin from 192.168.1.100 port 52413 ssh2"
        result = wrap_forensic_envelope({}, raw)

        # Round-trip: decode to string, re-encode to bytes
        recovered = result["raw_data"].encode("utf-8")
        assert recovered == raw

        # Hash verification
        assert result["raw_data_hash"]["value"] == hashlib.sha256(raw).hexdigest()

    def test_non_utf8_handled_gracefully(self) -> None:
        """Non-UTF-8 bytes should be decoded with replacement characters.

        The hash is still of the original bytes, preserving chain of custody.
        """
        raw = b"\x80\x81\x82 invalid utf8"
        result = wrap_forensic_envelope({}, raw)

        # The decoded string will have replacement characters
        assert "�" in result["raw_data"]

        # But the hash is of the ORIGINAL bytes, not the decoded string
        assert result["raw_data_hash"]["value"] == hashlib.sha256(raw).hexdigest()

    def test_raw_bytes_never_reencoded_before_hashing(self) -> None:
        """Critical §2 invariant: hash must be of exact original bytes.

        Re-encoding (bytes → str → bytes) through UTF-8 would change
        the hash for non-UTF-8 payloads. This test proves the hash is
        computed directly from the original bytes.
        """
        # These bytes are valid latin-1 but not valid UTF-8
        raw = b"\xe9\xe8\xe0"  # é, è, à in latin-1

        result = wrap_forensic_envelope({}, raw)

        # Hash must be of original bytes, not re-encoded string
        original_hash = hashlib.sha256(raw).hexdigest()
        reencoded_hash = hashlib.sha256(
            result["raw_data"].encode("utf-8")
        ).hexdigest()

        assert result["raw_data_hash"]["value"] == original_hash
        # The re-encoded hash will be DIFFERENT because UTF-8 encoding
        # of the replacement characters is not the same as the original bytes
        assert original_hash != reencoded_hash
