from log_parsers.isc_dhcp_server import IscDhcpServer as Ids
import pytest
import re


@pytest.fixture
def dhcp_ack_on():
    return "Jul 01 02:03:04 hostname dhcpd: DHCPACK on 1.2.3.4 to 00:01:02:03:04:05 (AAAAAAA) via eth0"


@pytest.fixture
def dhcp_ack_to():
    return "Jul 01 02:03:04 hostname dhcpd: DHCPACK to 2.3.4.5 (01:02:03:04:05:06) via eth1"


@pytest.fixture
def dhcp_inform():
    return "Jul 01 02:03:04 hostname dhcpd: DHCPINFORM from 3.4.5.6 via 4.5.6.7"


@pytest.fixture
def dhcp_nak():
    return "Jul 01 02:03:04 hostname dhcpd: DHCPNAK on 5.6.7.8 to 02:03:04:05:06:07 via 6.7.8.9"


@pytest.fixture
def dhcp_request():
    return "Jul 01 02:03:04 hostname dhcpd: DHCPREQUEST for 7.8.9.10 from 03:04:05:06:07:09 (BBBBBBBB) via eth1"


@pytest.fixture
def ids():
    return Ids()


@pytest.fixture
def re_type():
    return type(re.compile(r""))


def metadata_tests():
    return [
        ("date", "Jul 01 02:03:04"),
        ("hostname", "hostname"),
        ("daemon_name", "dhcpd"),
    ]


def dhcp_ack_on_tests():
    return [("message_type", "DHCPACK"), ("ip", "1.2.3.4"), ("hw", "00:01:02:03:04:05")]


def dhcp_ack_to_tests():
    return [("message_type", "DHCPACK"), ("ip", "2.3.4.5"), ("hw", "01:02:03:04:05:06")]


def dhcp_inform_tests():
    return []


def dhcp_nak_tests():
    return []


def dhcp_request_tests():
    return []


def test_ids_can_make_objects(ids):
    assert ids


@pytest.mark.parametrize("regex", ["meta", "ip", "hw", "via"])
def test_ids_regex(ids, re_type, regex):
    assert isinstance(ids.__dict__[regex], re_type)


@pytest.mark.parametrize("k,v", metadata_tests())
def test_ids_metadata_extracts_kv_pairs(ids, dhcp_ack_on, k, v):
    assert ids.metadata(dhcp_ack_on)[k] == v


@pytest.mark.parametrize("k,v", dhcp_ack_on_tests())
def test_ids_dchp_ack_extracts_kv_pairs(ids, dhcp_ack_on, k, v):
    assert ids.dhcp_message(dhcp_ack_on)[k] == v


@pytest.mark.parametrize("k,v", metadata_tests() + dhcp_ack_on_tests())
def test_ids_processes_dhcp_ack_on_extracts_kv_pairs(ids, dhcp_ack_on, k, v):
    assert ids.procecess(dhcp_ack_on)[k] == v


@pytest.mark.parametrize("k,v", metadata_tests() + dhcp_ack_to_tests())
def test_ids_processes_dhcp_ack_to(ids, dhcp_ack_to, k, v):
    assert ids.procecess(dhcp_ack_to)[k] == v
