import logfmtx


def test_render():
    assert logfmtx.render("{a}", {"a": 1}) == "1"
