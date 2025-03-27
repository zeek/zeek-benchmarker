"""
Collect information about the running machine.

Requires access to /sys for some of the DMI information
"""

import logging
import platform
from pathlib import Path

from . import models

logger = logging.getLogger(__name__)


def read_sys_dmi_id_file(
    name: str, base_path: Path = Path("/sys/devices/virtual/dmi/id")
) -> str:
    """
    Read /sys/devices/virtual/dmi/id/{name} and return the content, stripped.
    """
    try:
        return (base_path / name).read_text().strip()
    except FileNotFoundError as e:
        logger.warning("Could not open %s: %s", base_path / name, e)
        return ""


def get_cpu_model(path: Path = Path("/proc/cpuinfo")):
    """
    Seems platform.processor() isn't working well.

    Parse the first model name line out of /proc/cpuinfo

        model           : 142
        model name      : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
        stepping        : 12
    """
    with path.open() as f:
        for line in f:
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()

    return ""


def get_mem_total_bytes(path: Path = Path("/proc/meminfo")):
    """
    Parse /proc/meminfo for the MemTotal: line.

        MemTotal:       16073016 kB
        MemFree:         4273580 kB

    """
    with path.open() as f:
        for line in f:
            if line.startswith("MemTotal:"):
                value = line.split(":", 1)[1]
                kb, suffix = value.strip().split(" ", 1)
                if suffix != "kB" or not kb.isnumeric():
                    raise Exception(f"Unexpected value ${kb} / {suffix}")
                return int(kb) * 1024

    return 0


def get_machine() -> models.Machine:
    """
    Collect information for this system/machine.
    """
    kwargs = {}
    for k in ["sys_vendor", "product_uuid", "product_serial", "board_asset_tag"]:
        kwargs[f"dmi_{k}"] = read_sys_dmi_id_file(k)

    kwargs["os"] = platform.system()
    kwargs["architecture"] = platform.machine()
    kwargs["cpu_model"] = get_cpu_model()
    kwargs["mem_total_bytes"] = get_mem_total_bytes()

    return models.Machine(**kwargs)
