import logging.handlers
import textwrap

from . import config


class SMTPHandler(logging.handlers.SMTPHandler):
    """
    Custom SMTPHandler that looks up SMTP credentials in the configuration
    and dynamically creates the subject.
    """

    def __init__(
        self,
        *,
        subject_prefix: str,
        toaddrs: list[str] | str,
        cfg: config.Config = None,
    ):
        self.subject_prefix = subject_prefix
        cfg = cfg or config.get()
        super().__init__(
            toaddrs=toaddrs,
            subject=None,  # dynamically generated
            secure=(),  # always secure
            **cfg.smtp_settings._asdict(),
        )

    def getSubject(self, record):
        msg = textwrap.shorten(record.getMessage(), width=120)
        subject = f"{self.subject_prefix} {record.levelname}: {msg}"
        return subject
