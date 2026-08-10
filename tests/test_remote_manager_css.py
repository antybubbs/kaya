from pathlib import Path


REMOTE_CSS = Path(__file__).parents[1] / "app" / "static" / "css" / "remote.css"


def test_narrow_remote_host_typography_uses_rail_container():
    css = REMOTE_CSS.read_text(encoding="utf-8")
    container_rule = (
        "@container (max-width:280px){"
        ".remote-host-main strong{font-size:12px}"
        ".remote-host-main span.mono{font-size:10px}"
        ".remote-host-info .remote-cert-badge{font-size:10px}"
        ".remote-protocol-icon{font-size:10px}}"
    )

    assert ".remote-host-rail{" in css
    assert "container-type:inline-size" in css
    assert container_rule in css
    assert css.index(".remote-host-main strong{color:#f8fafc") < css.index(container_rule)
    assert "@media(max-width:1023px){.remote-host-main strong" not in css


def test_wide_remote_host_typography_stays_unchanged():
    css = REMOTE_CSS.read_text(encoding="utf-8")

    assert ".remote-host-main strong{color:#f8fafc;display:block;font-size:15px" in css
    assert (
        ".remote-host-main span{color:rgba(203,213,225,.62);"
        "display:block;font-size:12px"
    ) in css
