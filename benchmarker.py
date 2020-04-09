import hmac
import os
import requests
import shutil
import subprocess
import sys
import time
import traceback

import docker
from flask import Flask, request

# These two values need to be filled in before runtime will work. Note that the HMAC_KEY
# *must* be prefixed with 'b' or generating the digest to test with won't work.
HMAC_KEY = b''
DATA_FILE = ''

app = Flask(__name__)
app.config['CPU_SET'] = [22, 23]

docker_client = docker.from_env()

def verify_hmac(request_path, timestamp, request_digest):

        # Generate a new version of the digest on this side using the same information that the
        # caller use to generate their digest, and then compare the two for validity.
        hmac_msg = '{:s}-{:d}\n'.format(request_path, timestamp)
        local_digest = hmac.new(HMAC_KEY, hmac_msg.encode('utf-8'), 'sha256').hexdigest()
        if not hmac.compare_digest(local_digest, request_digest):
                app.logger.error("HMAC digest from request ({:s}) didn't match local digest ({:s})".format(request_digest, local_digest))
                return False

        return True

@app.route('/zeek', methods=['POST'])
def zeek():

        hmac_header = request.headers.get('Zeek-HMAC', None)
        if not hmac_header:
                return 'HMAC header missing from request', 403

        hmac_timestamp = int(request.headers.get('Zeek-HMAC-Timestamp', 0))
        if not hmac_timestamp:
                return 'HMAC timestamp missing from request', 403

        if not verify_hmac(request.path, hmac_timestamp, hmac_header):
                return 'HMAC validation failed', 403

        branch = request.args.get('branch', '')
        if not branch:
                return 'Branch argument required', 400

        build_url = request.args.get('build', None)
        if not build_url:
                return 'Build argument required', 400

        # Validate that the build URL is coming from Cirrus. This shouldn't be necessary but it's
        # easy sanity check.
        if not build_url.startswith('https://api.cirrus-ci.com/v1/artifact/build'):
                return 'Invalid build URL', 400

        build_hash = request.args.get('build_hash', '')
        if not build_hash:
                return 'Build hash argument required', 400

        # Validate the branch name. Disallow semi-colon and then use git's
        # method for testing for valid names.
        if ';' in branch:
                return 'Invalid branch name', 400

        ret = subprocess.call(['git', 'check-ref-format', '--branch', branch], stdout=subprocess.DEVNULL)
        if ret:
                return 'Invalid branch name', 400

        # Normalize the branch name to remove any non-alphanumeric characters so it's
        # safe to use as part of a path name. This is way overkill, but it's safer.
        normalized_branch = ''.join(x for x in branch if x.isalnum())
        normalized_branch += '-{:d}-{:d}'.format(int(hmac_timestamp), int(time.time()))
        base_path = os.path.dirname(os.path.abspath(__file__))
        work_path = os.path.join(base_path, normalized_branch)

        data_file_path = os.path.dirname(DATA_FILE)
        data_file_name = os.path.basename(DATA_FILE)
        tmpfs_path = '/mnt/data/tmpfs'

        result = None
        try:
                os.mkdir(work_path, mode=0o700)

                filename = os.path.join(work_path, build_url.rsplit('/', 1)[1])
                r = requests.get(build_url, allow_redirects=True)
                if not r:
                        raise RuntimeError('Failed to download build file')

                open(filename, 'wb').write(r.content)
                open('{:s}.md5'.format(filename), 'w').write('{:s} {:s}'.format(build_hash, filename))

                # Validate checksum of file before untarring it. There is a module in python
                # to do this, but I'm not going to read the whole file into memory to do it.
                ret = subprocess.call(['md5sum', '-c', '{:s}.md5'.format(filename)],
                                      stdout=subprocess.DEVNULL)
                if ret:
                        raise RuntimeError('Failed to validate checksum of file')

                # Build new docker image from the base image, tagged with the normalized branch name
                # so that we can use/delete it more easily.
                try:
                        docker_client.images.build(tag=normalized_branch, path=work_path, rm=True,
                                                   dockerfile=os.path.join(base_path, 'Dockerfile.runner'),
                                                   container_limits={'cpusetcpus': '{:d},{:d}'.format(
                                                           app.config['CPU_SET'][0], app.config['CPU_SET'][1])},
                                                   buildargs={'TMPFS_PATH': tmpfs_path})

                except docker.errors.BuildError as be:
                        app.logger.error(be)
                        raise RuntimeError('Failed to build runner image')

                # Run benchmark
                try:
                        # The docker API expects the seccomp to be the actual JSON from the file
                        # so trying to pass the filename fails (that works on the command-line).
                        # Load the json into a variable.
                        seccomp = open(os.path.join(base_path, 'zeek-seccomp.json'), 'r').read()

                        log_output = docker_client.containers.run(
                                image=normalized_branch,
                                remove=True, network='zeek-internal', cap_add=['SYS_NICE'],
                                security_opt=['seccomp={:s}'.format(seccomp)],
                                environment={
                                        'DATA_FILE_PATH': data_file_path,
                                        'DATA_FILE_NAME': data_file_name,
                                        'TMPFS_PATH': tmpfs_path,
                                        'DATA_FILE': os.path.join('/mnt/data/tmpfs', data_file_name),
                                        'ZEEKCPUS': '{:d},{:d}'.format(
                                                app.config['CPU_SET'][0], app.config['CPU_SET'][1])},
                                volumes={data_file_path: {'bind': data_file_path, 'mode': 'ro'}},
                                tmpfs={tmpfs_path: ''},
                                stderr=True)
                except docker.errors.ContainerError as ce:
                        app.logger.error(ce)
                        raise RuntimeError('Runner failed')

                # Destroy the container and image
                try:
                        docker_client.images.remove(image=normalized_branch, force=True)
                except docker.errors.APIError as ae:
                        app.logger.error(ae)
                        raise RuntimeError('Failed to destroy runner image')

        except RuntimeError as re:
                app.logger.error(traceback.format_exc())
                result = (str(re), 500)
        except:
                # log any other exceptions, but eat the string from them
                app.logger.error(traceback.format_exc())
                result = ('Failure occurred', 500)
        else:
                result = (log_output, 200)

        if os.path.exists(work_path):
                shutil.rmtree(work_path)

        return result

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=12345, threaded=False, ssl_context="adhoc")
