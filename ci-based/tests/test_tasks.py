import contextlib
import os
import pathlib
import unittest
from unittest import mock

import docker.client
import zeek_benchmarker.tasks


class TestContainerRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_spool = pathlib.Path("./test-spool-dir")
        cls.test_spool.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        with contextlib.suppress(FileNotFoundError):
            cls.test_spool.rmdir()

    def setUp(self):
        self._client_mock = mock.Mock(spec=docker.client.DockerClient)
        self._cr = zeek_benchmarker.tasks.ContainerRunner(client=self._client_mock)
        self.test_path = self.test_spool / "fake-job-id/build.tgz"

    def tearDown(self):
        with contextlib.suppress(FileNotFoundError):
            self.test_path.unlink()
        with contextlib.suppress(FileNotFoundError):
            self.test_path.parent.rmdir()

    def test_unpack_build(self):
        self.test_path.parent.mkdir()
        self.test_path.touch()
        self._cr.unpack_build(
            build_path=self.test_path,
            image="test-image",
            volume="test-volume",
        )
        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        # bash -x -c 'cmd'
        self.assertIn("-xzf fake-job-id/build.tgz", run_kwargs["command"][3])

    def test_unpack_build_space_quote(self):
        self.test_path = self.test_spool / "fake job id/space in build.tgz"
        self.test_path.parent.mkdir()
        self.test_path.touch()
        self._cr.unpack_build(
            build_path=self.test_path,
            image="test-image",
            volume="test-volume",
        )
        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        # bash -x -c 'cmd'
        self.assertIn("-xzf 'fake job id/space in build.tgz'", run_kwargs["command"][3])

    def test_unpack_no_spool_volume(self):
        self.test_path.parent.mkdir()
        self.test_path.touch()
        self._cr.unpack_build(
            build_path=self.test_path,
            image="test-image",
            volume="test-volume",
        )

        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        run_kwargs["mounts"]
        source_volume = run_kwargs["mounts"][1]
        self.assertEqual("bind", source_volume["Type"])
        self.assertEqual("test-spool-dir", source_volume["Source"])
        self.assertEqual("/source", source_volume["Target"])
        self.assertTrue(source_volume["ReadOnly"])

    @mock.patch.dict(os.environ, {"SPOOL_VOLUME": "test-spool-volume"})
    def test_unpack_spool_volume(self):
        self.test_path.parent.mkdir()
        self.test_path.touch()
        self._cr.unpack_build(
            build_path=self.test_path,
            image="test-image",
            volume="test-volume",
        )

        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        source_volume = run_kwargs["mounts"][1]
        self.assertEqual("volume", source_volume["Type"])
        self.assertEqual("test-spool-volume", source_volume["Source"])
        self.assertEqual("/source", source_volume["Target"])
        self.assertTrue(source_volume["ReadOnly"])
