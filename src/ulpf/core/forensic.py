"""Forensic envelope utilities for lossless log preservation.

These functions implement the chain-of-custody requirements from §2:
- Every parsed event carries the original ``raw_payload`` (as ``raw_data``).
- A ``raw_sha256`` hash of those exact bytes is computed **before** any
  transformation, truncation, or re-encoding.
- The fingerprint is stored in the OCSF ``raw_data_hash`` field.

The critical invariant is: ``hashlib.sha256(original_bytes).hexdigest()``
must always match the ``raw_data_hash.value`` on the emitted event.
If it doesn't, something in the pipeline mutated the evidence.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ulpf.core.enums import FingerprintAlgorithmId
from ulpf.core.objects import Fingerprint


def compute_raw_sha256(raw_bytes: bytes) -> str:
    """Compute the SHA-256 hex digest of raw log bytes.

    Takes raw bytes directly — never re-encodes — to preserve chain of
    custody. A single bit flip in the input must produce a completely
    different hash.

    Args:
        raw_bytes: The original, unmodified log bytes as received from
            the network or file.

    Returns:
        Lowercase hex string of the SHA-256 digest.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


def build_fingerprint(raw_bytes: bytes) -> Fingerprint:
    """Construct an OCSF ``Fingerprint`` object from raw log bytes.

    Always uses SHA-256 (algorithm_id=3) per ULPF policy. The algorithm
    is not configurable because chain-of-custody consistency requires
    a single, well-known hash function across the entire deployment.

    Args:
        raw_bytes: The original, unmodified log bytes.

    Returns:
        A validated ``Fingerprint`` with the SHA-256 digest.
    """
    return Fingerprint(
        algorithm="SHA-256",
        algorithm_id=FingerprintAlgorithmId.SHA256,
        value=compute_raw_sha256(raw_bytes),
    )


def wrap_forensic_envelope(event_data: dict[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    """Inject forensic envelope fields into an event dict before validation.

    This is called in the parser engine **after** field extraction but
    **before** Pydantic model construction. It ensures every event carries:
    - ``raw_data``: the original payload decoded as UTF-8 (lossy for
      non-UTF-8 sources, but the hash is of the original bytes).
    - ``raw_data_hash``: SHA-256 fingerprint for integrity/dedup.
    - ``raw_data_size``: byte count of the original payload.

    The ``raw_bytes`` argument must be the exact bytes as received from
    the syslog listener — never transformed, truncated, or re-encoded.

    Args:
        event_data: The partially-constructed event dict from the parser.
        raw_bytes: The original, unmodified log bytes.

    Returns:
        The event dict enriched with forensic envelope fields.
    """
    event_data["raw_data"] = raw_bytes.decode("utf-8", errors="replace")
    event_data["raw_data_hash"] = build_fingerprint(raw_bytes).model_dump()
    event_data["raw_data_size"] = len(raw_bytes)
    return event_data
