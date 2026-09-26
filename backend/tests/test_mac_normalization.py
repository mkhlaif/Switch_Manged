import pytest

from app.parsers.common import InvalidMacError, format_mac, is_multicast, normalize_mac


@pytest.mark.parametrize("value", [
    "00:11:22:33:44:55",
    "00-11-22-33-44-55",
    "0011.2233.4455",
    "001122334455",
    "  00:11:22:33:44:55  ",
    "00:11:22:33:44:55".upper(),
])
def test_accepted_formats_normalize_to_12_hex(value):
    assert normalize_mac(value) == "001122334455"


def test_uppercase_hex_is_lowercased():
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"


@pytest.mark.parametrize("value", [
    "", "00:11:22:33:44", "00:11:22:33:44:55:66", "00:11-22:33:44:55", "0011.2233.445",
    "00112233445g", "zz:11:22:33:44:55", "0011:2233:4455", "00 11 22 33 44 55", "001122334455;",
    "00:11:22:33:44:55\nshow system",
])
def test_invalid_formats_rejected(value):
    with pytest.raises(InvalidMacError):
        normalize_mac(value)


def test_format_mac_for_aos_cli():
    assert format_mac("001122334455") == "00:11:22:33:44:55"
    with pytest.raises(InvalidMacError):
        format_mac("00112233445")


def test_multicast_bit():
    assert is_multicast("01005e000001")
    assert not is_multicast("001122334455")
