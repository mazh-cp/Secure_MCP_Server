import pytest

from secure_mcp.edge.verdict import ALLOW, BLOCK, WARN, UrlPolicy, classify_response, decide


@pytest.mark.parametrize("resp,expected", [
    ({"classification": "Malicious"}, "malicious"),
    ({"verdict": "MALWARE"}, "malicious"),
    ({"category": "Phishing"}, "phishing"),
    ({"risk": "Suspicious"}, "suspicious"),
    ({"reputation": "benign"}, "benign"),
    ({"reputation": "clean"}, "benign"),
    ({"something": "weird"}, "unknown"),
    ({}, "unknown"),
])
def test_classify_response(resp, expected):
    assert classify_response(resp) == expected


def test_decide_blocks_malicious_and_phishing_by_default():
    p = UrlPolicy()
    assert decide("malicious", p)["action"] == BLOCK
    assert decide("phishing", p)["action"] == BLOCK


def test_decide_suspicious_warns_unless_policy_blocks():
    assert decide("suspicious", UrlPolicy())["action"] == WARN
    assert decide("suspicious", UrlPolicy(block_suspicious=True))["action"] == BLOCK


def test_decide_allows_benign_and_unknown():
    assert decide("benign", UrlPolicy())["action"] == ALLOW
    assert decide("unknown", UrlPolicy())["action"] == ALLOW


def test_decide_respects_disabled_blocking():
    p = UrlPolicy(block_malicious=False, block_phishing=False)
    assert decide("malicious", p)["action"] == ALLOW
    assert decide("phishing", p)["action"] == ALLOW
