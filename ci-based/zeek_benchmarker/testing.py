import os
import pathlib
import tempfile
import unittest

import alembic.command
import alembic.config


class TestWithDatabase(unittest.TestCase):
    """
    A TestCase that initalizes a temporary database including migration.
    """

    def setUp(self):
        self.database_file = tempfile.NamedTemporaryFile(delete=False, dir=".")
        alembic_config = alembic.config.Config()
        script_location = pathlib.Path(__file__).parent.parent / "alembic"
        alembic_config.set_main_option("script_location", str(script_location))
        alembic_config.set_main_option(
            "sqlalchemy.url", f"sqlite:///{self.database_file.name}"
        )
        alembic.command.upgrade(alembic_config, "head")

    def tearDown(self):
        os.unlink(self.database_file.name)
