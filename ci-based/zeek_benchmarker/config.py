import os
import typing

import yaml


class SMTPSettings(typing.NamedTuple):
    mailhost: tuple[str, int]
    credentials: tuple[str, str]
    fromaddr: str


class Config:
    _config: "Config" = None

    def __init__(self, d: dict[str, typing.Any]):
        self._d = d

    @property
    def work_dir(self) -> str:
        return self._d["WORK_DIR"]

    @property
    def tar_timeout(self) -> str:
        return self._d.get("TAR_TIMEOUT", 20)

    @property
    def zeek_cpus(self) -> str:
        return ",".join(str(c) for c in self._d["CPU_SET"])

    def __getitem__(self, k: str, default: typing.Any = None):
        """
        Allow dictionary key lookups.
        """
        return self._d.get(k, default)

    @property
    def smtp_settings(self) -> SMTPSettings:
        smtp = self["smtp"]
        mailhost = (smtp["host"], int(smtp.get("port", 587)))
        credentials = (smtp["credentials"]["username"], smtp["credentials"]["password"])

        return SMTPSettings(
            mailhost=mailhost,
            credentials=credentials,
            fromaddr=smtp["fromaddr"],
        )


def get():
    """
    Lazily load the config.
    """
    filename = os.getenv("ZEEK_BENCHMARKER_CONFIG", "config.yml")
    if Config._config is None:
        with open(filename) as fp:
            Config._config = Config(yaml.safe_load(fp))

    return Config._config
