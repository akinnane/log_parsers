from log_parsers.named import Named
import pytest
import re


@pytest.fixture
def dns_query():
    return "Jul 01 02:03:04 hostname named[123]: client 1.2.3.4#12345: query: example.com IN A + (2.3.4.5)"


@pytest.fixture
def named():
    return Named()


@pytest.fixture
def re_type():
    return type(re.compile(r""))


def metadata_tests():
    return [
        ("date", "Jul 01 02:03:04"),
        ("hostname", "hostname"),
        ("daemon_name", "named[123]"),
    ]


def dns_query_tests():
    return [("client", "1.2.3.4"), ("query", "example.com"), ("record_type", "A")]


def test_named_can_make_objects(named):
    assert named


@pytest.mark.parametrize("regex", ["meta", "client", "query", "record_type"])
def test_named_regex(named, re_type, regex):
    assert isinstance(named.__dict__[regex], re_type)


@pytest.mark.parametrize("k,v", metadata_tests())
def test_named_metadata_extracts_kv_pairs(named, dns_query, k, v):
    assert named.metadata(dns_query)[k] == v


@pytest.mark.parametrize("k,v", dns_query_tests())
def test_named_dns_query_extracts_kv_pairs(named, dns_query, k, v):
    assert named.dns_query(dns_query)[k] == v


@pytest.mark.parametrize("k,v", metadata_tests() + dns_query_tests())
def test_named_processes_on_extracts_kv_pairs(named, dns_query, k, v):
    assert named.procecess(dns_query)[k] == v
