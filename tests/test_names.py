import pytest

from slopstop.models import Ecosystem
from slopstop.names import InvalidPackageName, normalize, url_path_segment, validate


def test_valid_pypi_names():
    assert validate(Ecosystem.PYPI, "requests") == "requests"
    assert validate(Ecosystem.PYPI, "scikit_learn") == "scikit-learn"
    assert validate(Ecosystem.PYPI, "Flask") == "flask"


def test_valid_npm_scoped_name():
    assert validate(Ecosystem.NPM, "@types/node") == "@types/node"
    assert validate(Ecosystem.NPM, "react") == "react"


def test_pypi_normalization_collapses_separators():
    assert normalize(Ecosystem.PYPI, "Foo._-Bar") == "foo-bar"


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "..",
        "/root",
        ".hidden",
        "_leading",
        "has space",
        "x" * 300,
        "",
    ],
)
def test_rejects_hostile_or_malformed_names(bad):
    with pytest.raises(InvalidPackageName):
        validate(Ecosystem.PYPI, bad)


def test_url_segment_encodes_but_keeps_scope_syntax():
    assert url_path_segment("@types/node") == "@types/node"
    assert url_path_segment("weird name") == "weird%20name"
