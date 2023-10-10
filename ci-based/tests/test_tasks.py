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
        self._container_mock = mock.Mock(spec=docker.models.containers.Container)
        self._client_mock.containers.run.return_value = self._container_mock
        self._container_mock.wait.return_value = {"StatusCode": 0}
        self._container_mock.logs.return_value = "fake-logs"

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

    def test__runc(self):
        result = self._cr.runc(
            image="test-image",
            command="test-exit 1",
            env={},
            seccomp_profile={},
            install_volume="test-install-volume",
            install_target="/test/install",
            test_data_volume="test_data",
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual("fake-logs", result.stdout)
        self.assertEqual("fake-logs", result.stderr)

    def test__runc_command__failed(self):
        self._container_mock.wait.return_value = {"StatusCode": 1}

        with self.assertRaises(zeek_benchmarker.tasks.CommandFailed):
            self._cr.runc(
                image="test-image",
                command="test-exit 1",
                env={},
                seccomp_profile={},
                install_volume="test-install-volume",
                install_target="/test/install",
                test_data_volume="test_data",
            )

    def test__runc__tmpfs(self):
        self._cr.runc(
            image="test-image",
            command="test-exit 1",
            env={},
            seccomp_profile={},
            install_volume="test-install-volume",
            install_target="/test/install",
            test_data_volume="test_data",
        )

        # Regression test for env not being populated with TMPFS_PATH
        run_kwargs = self._client_mock.containers.run.call_args[1]
        self.assertEqual("/mnt/data/tmpfs", run_kwargs["environment"]["TMPFS_PATH"])
        self.assertEqual("/run", run_kwargs["environment"]["RUN_PATH"])
        self.assertEqual("", run_kwargs["tmpfs"]["/mnt/data/tmpfs"])
        self.assertEqual("", run_kwargs["tmpfs"]["/run"])


class TestZeekJob(unittest.TestCase):
    def setUp(self):
        self.job = zeek_benchmarker.tasks.ZeekJob(
            build_url="test-url",
            build_hash="test-hash",
            original_branch="test-original-branch",
            normalized_branch="test-normalized-branch",
            commit="test-commit",
            job_id="test-job-id",
        )

    @mock.patch("zeek_benchmarker.tasks.ZeekJob.run_zeek_test")
    def test_process(self, run_zeek_test_mock):
        # This uses the Config.get() singleton call to get access
        # to the
        # config.yml and confi-tests.yml stored in this repo.
        # We use that for basic smoke testing that reading the
        # config worked.
        self.job._process()

        tests = [c.args[0] for c in run_zeek_test_mock.call_args_list]
        ids = [t.test_id for t in tests]
        self.assertGreater(len(ids), 10)
        self.assertIn("micro-table-ops-copy", ids)
        self.assertIn("pcap-500k-syns", ids)
