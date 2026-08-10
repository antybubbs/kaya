from pathlib import Path


REMOTE_CSS = Path(__file__).parents[1] / "app" / "static" / "css" / "remote.css"


def test_remote_host_typography_uses_fluid_rail_container_units():
    css = REMOTE_CSS.read_text(encoding="utf-8")

    assert ".remote-host-rail{" in css
    assert "container-type:inline-size" in css
    assert "font-size:clamp(12px,calc(7.7px + 2.15cqi),15px)" in css
    assert css.count("font-size:clamp(10px,calc(7.15px + 1.425cqi),12px)") == 2
    assert "@container (max-width:280px)" not in css
    assert "@media(max-width:1023px){.remote-host-main strong" not in css


def test_wide_remote_host_typography_stays_unchanged():
    css = REMOTE_CSS.read_text(encoding="utf-8")

    assert ".remote-host-main strong{color:#f8fafc;display:block;font-size:15px" in css
    assert (
        ".remote-host-main span{color:rgba(203,213,225,.62);"
        "display:block;font-size:12px"
    ) in css


def test_fluid_remote_typography_bounds_across_supported_rail_widths():
    def fluid(width, minimum, intercept, cqi_rate, maximum):
        return max(minimum, min(intercept + cqi_rate * width / 100, maximum))

    hostname = [round(fluid(width, 12, 7.7, 2.15, 15), 3) for width in (200, 310, 340, 520)]
    secondary = [round(fluid(width, 10, 7.15, 1.425, 12), 3) for width in (200, 310, 340, 520)]

    assert hostname == [12, 14.365, 15, 15]
    assert secondary == [10, 11.568, 11.995, 12]
