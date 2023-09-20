import logging
import unittest
from unittest import mock

import zeek_benchmarker.config
import zeek_benchmarker.logging


@mock.patch("smtplib.SMTP")
class TestSmtpHandler(unittest.TestCase):
    cfg = zeek_benchmarker.config.Config(
        {
            "smtp": {
                "credentials": {
                    "username": "test-smtp-user",
                    "password": "test-smtp-password",
                },
                "host": "test.example.com",
                "fromaddr": "test@test.example.com",
            }
        }
    )

    def test_error_logging(self, smtp_cls):
        handler = zeek_benchmarker.logging.SMTPHandler(
            subject_prefix="test-prefix", toaddrs=["a", "b"], cfg=self.cfg
        )

        logger = logging.Logger("test-logger")
        logger.addHandler(handler)
        logger.error("This is an error")

        smtp_mock = smtp_cls.return_value
        smtp_mock.login.assert_called_with("test-smtp-user", "test-smtp-password")
        # Check the email that was sent
        msg = smtp_mock.send_message.call_args[0][0]
        self.assertEqual(msg["Subject"], "test-prefix ERROR: This is an error")
        self.assertEqual(msg["From"], "test@test.example.com")
        self.assertEqual(msg.get_content(), "This is an error\n")
