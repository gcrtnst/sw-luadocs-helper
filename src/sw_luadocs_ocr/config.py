import toml


def check_capture_config(capture_cfg):
    def check(key, *, normalize_fn=None, vmin=None, vmax=None):
        if key not in capture_cfg:
            raise ValueError(f"{key} is missing")
        if normalize_fn is not None:
            capture_cfg[key] = normalize_fn(capture_cfg[key])
        if vmin is not None and capture_cfg[key] < vmin:
            raise ValueError(f"{key} is less than {vmin}")
        if vmax is not None and vmax < capture_cfg[key]:
            raise ValueError(f"{key} is greater than {vmax}")

    if not isinstance(capture_cfg, dict):
        raise ValueError("capture_cfg is not dict")

    check("win_title", normalize_fn=str)
    check("win_text", normalize_fn=str)
    check("win_exclude_title", normalize_fn=str)
    check("win_exclude_text", normalize_fn=str)

    check("screen_width", normalize_fn=int, vmin=1)
    check("screen_height", normalize_fn=int, vmin=1)

    check("scroll_x", normalize_fn=int, vmin=0, vmax=capture_cfg["screen_width"] - 1)
    check("scroll_y", normalize_fn=int, vmin=0, vmax=capture_cfg["screen_height"] - 1)
    check("scroll_page_n", normalize_fn=int, vmin=1)
    check("scroll_once_n", normalize_fn=int, vmin=1)
    check("scroll_threshold", normalize_fn=int, vmin=0)

    check(
        "capture_region_x1",
        normalize_fn=int,
        vmin=0,
        vmax=capture_cfg["screen_width"] - 1,
    )
    check(
        "capture_region_y1",
        normalize_fn=int,
        vmin=0,
        vmax=capture_cfg["screen_height"] - 1,
    )
    check(
        "capture_region_x2",
        normalize_fn=int,
        vmin=capture_cfg["capture_region_x1"],
        vmax=capture_cfg["screen_width"] - 1,
    )
    check(
        "capture_region_y2",
        normalize_fn=int,
        vmin=capture_cfg["capture_region_y1"],
        vmax=capture_cfg["screen_height"] - 1,
    )
    check("capture_template_ratio", normalize_fn=float, vmin=0, vmax=1)

    check("activate_sleep_secs", normalize_fn=float, vmin=0)
    check("scroll_sleep_secs", normalize_fn=float, vmin=0)


def load_toml(f):
    cfg = toml.load(f)
    check_capture_config(cfg["capture"])
    return cfg
