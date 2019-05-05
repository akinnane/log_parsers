from log_parsers.iptables import IpTables
import pytest
import re
from datetime import datetime


@pytest.fixture
def ipt_log():
    return "Jul 01 02:03:04 hostname kernel: FW DENY_INPUT: IN=eth0 OUT=eth1 MAC=ff:ff:ff:ff:ff:ff:01:02:03:04:05:06:07:08 SRC=1.2.3.4 DST=2.3.4.5 LEN=01 TOS=0x00 PREC=0x01 TTL=128 ID=555 PROTO=TCP SPT=1234 DPT=2345 LEN=02"


@pytest.fixture
def ipt():
    return IpTables()


@pytest.fixture
def re_type():
    return type(re.compile(r""))


def metadata_tests():
    return [
        ("date", datetime(datetime.now().year, 7, 1, 2, 3, 4)),
        ("hostname", "hostname"),
        ("daemon_name", "kernel"),
    ]


def ipt_log_tests():
    return [
        ("in", "eth0"),
        ("out", "eth1"),
        ("mac", "ff:ff:ff:ff:ff:ff:01:02:03:04:05:06:07:08"),
        ("src", "1.2.3.4"),
        ("dst", "2.3.4.5"),
        ("tos", "0x00"),
        ("prec", "0x01"),
        ("ttl", "128"),
        ("id", "555"),
        ("proto", "TCP"),
        ("spt", "1234"),
        ("dpt", "2345"),
    ]


def test_ipt_can_make_objects(ipt):
    assert ipt


@pytest.mark.parametrize(
    "regex",
    [
        "inn",
        "out",
        "mac",
        "src",
        "dst",
        "tos",
        "prec",
        "ttl",
        "id",
        "proto",
        "spt",
        "dpt",
    ],
)
def test_ipt_regex(ipt, re_type, regex):
    assert isinstance(ipt.__dict__[regex], re_type)


@pytest.mark.parametrize("k,v", metadata_tests())
def test_ipt_metadata_extracts_kv_pairs(ipt, ipt_log, k, v):
    assert ipt.metadata(ipt_log)[k] == v


@pytest.mark.parametrize("k,v", ipt_log_tests())
def test_ipt_log_extracts_kv_pairs(ipt, ipt_log, k, v):
    assert ipt.ipt_log(ipt_log)[k] == v


@pytest.mark.parametrize("k,v", metadata_tests() + ipt_log_tests())
def test_ipt_processes_on_extracts_kv_pairs(ipt, ipt_log, k, v):
    assert ipt.procecess(ipt_log)[k] == v
