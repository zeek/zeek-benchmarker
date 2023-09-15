import os
import typing

import yaml


class Config:
    _config: "Config" = None

    def __init__(self, d: typing.Dict[str, typing.Any]):
        self._d = d

    @property
    def work_dir(self) -> str:
        return self._d["WORK_DIR"]

    @property
    def tar_timeout(self) -> str:
        return self._d.get("TAR_TIMEOUT", 30)

    @property
    def zeek_cpus(self) -> str:
        return ",".join(str(c) for c in self._d["CPU_SET"])

    def __getitem__(self, k: str, default: typing.Any = None):
        """
        Allow dictionary key lookups.
        """
        return self._d.get(k, default)


def get():
    """
    Lazily load the config.
    """
    filename = os.getenv("ZEEK_BENCHMARKER_CONFIG", "config.yml")
    if Config._config is None:
        with open(filename) as fp:
            Config._config = Config(yaml.safe_load(fp))

    return Config._config
