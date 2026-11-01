import pytest
from validators import detect_type

VALID = [
    ("8.8.8.8", "ip"), ("2001:4860:4860::8888", "ip"),
    ("example.com", "domain"), ("Sub.Example.CO.uk", "domain"),
    ("https://example.com/path?q=1", "url"), ("http://1.2.3.4/x", "url"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("hxxps://evil[.]example[.]com/a", "url"),
    ("  8.8.4.4  ", "ip"),
]
INVALID = ["", "   ", "999.999.999.999", "not a domain", "example", "-bad.com",
           "ftp//x.com", "javascript:alert(1)", "d41d8cd98f00b204e9800998ecf8427",
           "zzzz8cd98f00b204e9800998ecf8427e", "http://", "a" * 3000]


@pytest.mark.parametrize("val,expected", VALID)
def test_valid(val, expected):
    assert detect_type(val)[1] == expected


@pytest.mark.parametrize("val", INVALID)
def test_invalid(val):
    assert detect_type(val)[1] is None
