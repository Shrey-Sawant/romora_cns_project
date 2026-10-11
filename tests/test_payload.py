import pytest

from core.payload import (
    EXPECTED_CT_LEN,
    EXPECTED_SIG_LEN,
    MAGIC,
    TOTAL_PAYLOAD_SIZE,
    VERSION,
    build_payload,
    parse_payload,
)


def test_build_and_parse_payload_round_trip():
    dummy_ct = b"C" * EXPECTED_CT_LEN
    dummy_sig = b"S" * EXPECTED_SIG_LEN

    payload = build_payload(dummy_ct, dummy_sig)
    assert len(payload) == TOTAL_PAYLOAD_SIZE

    recovered_ct, recovered_sig = parse_payload(payload)
    assert recovered_ct == dummy_ct
    assert recovered_sig == dummy_sig


def test_build_payload_rejects_wrong_lengths():
    with pytest.raises(ValueError, match="Expected RSA ciphertext"):
        build_payload(b"short", b"S" * EXPECTED_SIG_LEN)

    with pytest.raises(ValueError, match="Expected ECDSA signature"):
        build_payload(b"C" * EXPECTED_CT_LEN, b"short")


def test_parse_payload_rejects_bad_magic():
    dummy_ct = b"C" * EXPECTED_CT_LEN
    dummy_sig = b"S" * EXPECTED_SIG_LEN
    payload = bytearray(build_payload(dummy_ct, dummy_sig))
    payload[0:4] = b"FAKE"

    with pytest.raises(ValueError, match="Invalid payload magic identifier"):
        parse_payload(bytes(payload))


def test_parse_payload_rejects_bad_version():
    dummy_ct = b"C" * EXPECTED_CT_LEN
    dummy_sig = b"S" * EXPECTED_SIG_LEN
    payload = bytearray(build_payload(dummy_ct, dummy_sig))
    payload[4] = 0x02  # version 2

    with pytest.raises(ValueError, match="Unsupported payload version"):
        parse_payload(bytes(payload))


def test_parse_payload_rejects_truncated_data():
    dummy_ct = b"C" * EXPECTED_CT_LEN
    dummy_sig = b"S" * EXPECTED_SIG_LEN
    payload = build_payload(dummy_ct, dummy_sig)

    # Less than header
    with pytest.raises(ValueError, match="Payload truncated"):
        parse_payload(payload[:5])

    # Truncated body
    with pytest.raises(ValueError, match="Payload size mismatch"):
        parse_payload(payload[:-10])
