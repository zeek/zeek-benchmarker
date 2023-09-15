import pathlib
import unittest
from unittest import mock

import docker.client
import zeek_benchmarker.tasks


class TestContainerRunner(unittest.TestCase):
    def setUp(self):
        self._client_mock = mock.Mock(spec=docker.client.DockerClient)
        self._cr = zeek_benchmarker.tasks.ContainerRunner(client=self._client_mock)
        self.test_path = pathlib.Path("./build.tgz")

    def tearDown(self):
        try:
            self.test_path.unlink()
        except FileNotFoundError:
            pass

    def test_unpack_build(self):
        self.test_path.touch()
        self._cr.unpack_build(self.test_path, volume="test-volume")
        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        # bash -x -c 'cmd'
        self.assertIn("-xzf build.tgz", run_kwargs["command"][3])

    def test_unpack_build_space_quote(self):
        self.test_path = pathlib.Path("./space in build.tgz")
        self.test_path.touch()
        self._cr.unpack_build(self.test_path, volume="test-volume")
        self._client_mock.containers.run.assert_called_once()
        run_kwargs = self._client_mock.containers.run.call_args[1]
        # bash -x -c 'cmd'
        self.assertIn("-xzf 'space in build.tgz'", run_kwargs["command"][3])
