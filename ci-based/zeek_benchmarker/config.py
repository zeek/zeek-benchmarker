import os
import typing

import yaml


class SMTPSettings(typing.NamedTuple):
    mailhost: tuple[str, int]
    credentials: tuple[str, str]
    fromaddr: str


class Config:
    _config: typing.Optional["Config"] = None

    def __init__(self, d: dict[str, typing.Any]):
        self._d = d
        self._tests_d: dict[str, typing.Any] | None = None

    @property
    def work_dir(self) -> str:
        return self._d["WORK_DIR"]

    @property
    def tar_timeout(self) -> str:
        return self._d.get("TAR_TIMEOUT", 20)

    @property
    def zeek_cpus(self) -> str:
        return ",".join(str(c) for c in self._d["CPU_SET"])

    @property
    def run_count(self) -> int:
        return self._d["RUN_COUNT"]

    @property
    def zeek_tests(self) -> list[dict[str, typing.Any]]:
        if self._tests_d is None:
            with open(self["TESTS_FILE"]) as fp:
                self._tests_d = yaml.safe_load(fp)

        return self._tests_d["ZEEK_TESTS"]

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


def get() -> Config:
    """
    Lazily load the config.
    """
    filename = os.getenv("ZEEK_BENCHMARKER_CONFIG", "config.yml")
    if Config._config is None:
        with open(filename) as fp:
            Config._config = Config(yaml.safe_load(fp))

    return Config._config
