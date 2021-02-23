import hmac
import os
import requests
import shutil
import subprocess
import sys
import time
import traceback
import sqlite3
import re
from datetime import datetime, timedelta

import docker
from flask import Flask, request

# These values need to be filled in before runtime will work. Note that the HMAC_KEY
# *must* be prefixed with 'b' or generating the digest to test with won't work.
HMAC_KEY = b''

# Path to a pcap file used by the zeek endpoint.
DATA_FILE = ''

# Path to a cluster-config data file used by the broker endpoint.
BROKER_CONFIG_FILE = ''

# Path to an sqlite database file that stores the metrics once they're completed for
# viewing on grafana, etc.
DATABASE_FILE = ''

# This is the number of loops that the zeek benchmarker will run against the data file
# in order to average out noise in the process. A value of 3 is a reasonable balance
# for overall runtime for each request.
RUN_COUNT = 3

app = Flask(__name__)
app.config['CPU_SET'] = [22, 23]

docker_client = docker.from_env()

def verify_hmac(request_path, timestamp, request_digest, build_hash):

        # Generate a new version of the digest on this side using the same information that the
        # caller use to generate their digest, and then compare the two for validity.
        hmac_msg = '{:s}-{:d}-{:s}\n'.format(request_path, timestamp, build_hash)
        local_digest = hmac.new(HMAC_KEY, hmac_msg.encode('utf-8'), 'sha256').hexdigest()
        if not hmac.compare_digest(local_digest, request_digest):
                app.logger.error("HMAC digest from request ({:s}) didn't match local digest ({:s})".format(request_digest, local_digest))
                return False

        return True

def parse_request(req):

        req_vals = {}
        branch = request.args.get('branch', '')
        if not branch:
                return 'Branch argument required', 400

        build_url = request.args.get('build', None)
        if not build_url:
                return 'Build argument required', 400

        # Validate that the build URL is either from Cirrus, or a local file from the local host.
        if build_url.startswith('https://api.cirrus-ci.com/v1/artifact/build'):
                remote_build = True

                # Remote requests are required to be signed with HMAC and have an sha256 hash
                # of the build file passed with them.
                hmac_header = request.headers.get('Zeek-HMAC', None)
                if not hmac_header:
                        return 'HMAC header missing from request', 403

                hmac_timestamp = int(request.headers.get('Zeek-HMAC-Timestamp', 0))
                if not hmac_timestamp:
                        return 'HMAC timestamp missing from request', 403

                # Double check that the timestamp is within the last 15 minutes UTC to avoid someone
                # trying to reuse it.
                ts = datetime.utcfromtimestamp(hmac_timestamp)
                utc = datetime.utcnow()
                delta = utc - ts

                if delta > timedelta(minutes=15):
                        return 'HMAC timestamp is outside of the valid range', 403

                req_vals['build_hash'] = request.args.get('build_hash', '')
                if not req_vals['build_hash']:
                        return 'Build hash argument required', 400

                if not verify_hmac(request.path, hmac_timestamp, hmac_header, req_vals['build_hash']):
                        return 'HMAC validation failed', 403

        elif build_url.startswith('file://') and request.remote_addr == '127.0.0.1':
                remote_build = False
        else:
                return 'Invalid build URL', 400

        # Validate the branch name. Disallow semi-colon and then use git's
        # method for testing for valid names.
        if ';' in branch:
                return 'Invalid branch name', 400

        ret = subprocess.call(['git', 'check-ref-format', '--branch', branch], stdout=subprocess.DEVNULL)
        if ret:
                return 'Invalid branch name', 400

        # Normalize the branch name to remove any non-alphanumeric characters so it's
        # safe to use as part of a path name. This is way overkill, but it's safer.
        # Docker requires it to be all lowercase as well.
        normalized_branch = ''.join(x for x in branch if x.isalnum()).lower()
        if remote_build:
                normalized_branch += '-{:d}-{:d}'.format(int(hmac_timestamp), int(time.time()))
        else:
                normalized_branch += '-local-{:d}'.format(int(time.time()))

        req_vals['build_url'] = build_url
        req_vals['remote'] = remote_build
        req_vals['normalized_branch'] = normalized_branch
        return req_vals

@app.route('/zeek', methods=['POST'])
def zeek():

        req_vals = parse_request(request)
        if not isinstance(req_vals, dict):
                return req_vals

        base_path = os.path.dirname(os.path.abspath(__file__))
        work_path = os.path.join(base_path, req_vals['normalized_branch'])

        data_file_path = os.path.dirname(DATA_FILE)
        data_file_name = os.path.basename(DATA_FILE)
        tmpfs_path = '/mnt/data/tmpfs'
        filename = req_vals['build_url'].rsplit('/', 1)[1]

        result = None
        try:
                os.mkdir(work_path, mode=0o700)

                if req_vals['remote']:
                        dockerfile = 'Dockerfile.zeek-runner'
                        file_path = os.path.join(work_path, filename)
                        r = requests.get(req_vals['build_url'], allow_redirects=True)
                        if not r:
                                raise RuntimeError('Failed to download build file')

                        open(file_path, 'wb').write(r.content)
                        open('{:s}.sha256'.format(file_path), 'w').write('{:s} {:s}'.format(req_vals['build_hash'], file_path))

                        # Validate checksum of file before untarring it. There is a module in python
                        # to do this, but I'm not going to read the whole file into memory to do it.
                        ret = subprocess.call(['sha256sum', '-c', '{:s}.sha256'.format(file_path)],
                                              stdout=subprocess.DEVNULL)
                        if ret:
                                raise RuntimeError('Failed to validate build file checksum')
                else:
                        dockerfile = 'Dockerfile.zeek-localrunner'
                        file_path = req_vals['build_url'][7:]
                        shutil.copytree(file_path, os.path.join(work_path, filename))

                # Build new docker image from the base image, tagged with the normalized branch name
                # so that we can use/delete it more easily.
                try:
                        docker_client.images.build(tag=req_vals['normalized_branch'], path=work_path, rm=True,
                                                   dockerfile=os.path.join(base_path, dockerfile),
                                                   container_limits={'cpusetcpus': '{:d},{:d}'.format(
                                                           app.config['CPU_SET'][0], app.config['CPU_SET'][1])},
                                                   buildargs={'TMPFS_PATH': tmpfs_path,
                                                              'BUILD_FILE_NAME': filename})

                except docker.errors.BuildError as build_err:
                        app.logger.error(build_err)
                        raise RuntimeError('Failed to build runner image')

                total_time = 0
                total_mem = 0

                for i in range(RUN_COUNT):
                        # Run benchmark
                        try:
                                # The docker API expects the seccomp to be the actual JSON from the file
                                # so trying to pass the filename fails (that works on the command-line).
                                # Load the json into a variable.
                                seccomp = open(os.path.join(base_path, 'zeek-seccomp.json'), 'r').read()

                                log_output = docker_client.containers.run(
                                        image=req_vals['normalized_branch'],
                                        remove=True, network='zeek-internal', cap_add=['SYS_NICE'],
                                        security_opt=['seccomp={:s}'.format(seccomp)],
                                        environment={
                                                'BUILD_FILE_NAME': filename,
                                                'DATA_FILE_PATH': data_file_path,
                                                'DATA_FILE_NAME': data_file_name,
                                                'TMPFS_PATH': tmpfs_path,
                                                'ZEEKCPUS': '{:d},{:d}'.format(
                                                        app.config['CPU_SET'][0], app.config['CPU_SET'][1])},
                                        volumes={data_file_path: {'bind': data_file_path, 'mode': 'ro'}},
                                        tmpfs={tmpfs_path: ''},
                                        stderr=True)

                                # Output from the benchmark script is a time in seconds followed by a memory
                                # value in bytes
                                [time_elapsed, max_mem] = log_output.split()
                                total_time += float(time_elapsed)
                                total_mem += int(max_mem)
                        except docker.errors.ContainerError as cont_err:
                                app.logger.error(cont_err)
                                raise RuntimeError('Runner failed')

                avg_time = total_time / float(RUN_COUNT)
                avg_mem = int(total_mem / float(RUN_COUNT))
                log_output = 'Averaged over {:d} passes:\nTime Spent: {:.3f} seconds\nMax memory usage: {:d} bytes'.format(
                        RUN_COUNT, avg_time, avg_mem)

                db_conn = sqlite3.connect(DATABASE_FILE)
                c = db_conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS "zeek" (
                          "id" integer primary key autoincrement not null,
                          "stamp" datetime default (datetime('now', 'localtime')),
                          "time_spent" float not null,
                          "memory_used" float not null)''')

                c.execute('insert into zeek (time_spent, memory_used) values (?, ?)', [avg_time, avg_mem])
                db_conn.commit()
                db_conn.close()

        except RuntimeError as rt_err:
                app.logger.error(traceback.format_exc())
                result = (str(rt_err), 500)
        except:
                # log any other exceptions, but eat the string from them
                app.logger.error(traceback.format_exc())
                result = ('Failure occurred', 500)
        else:
                result = (log_output, 200)

        # Destroy the container and image
        try:
                docker_client.images.remove(image=req_vals['normalized_branch'], force=True)
        except docker.errors.APIError as api_err:
                app.logger.error(api_err)
                result = ('Failed to destroy runner image', 500)

        if os.path.exists(work_path):
                shutil.rmtree(work_path)

        return result

@app.route('/broker', methods=['POST'])
def broker():

        req_vals = parse_request(request)
        if not isinstance(req_vals, dict):
                return req_vals

        base_path = os.path.dirname(os.path.abspath(__file__))
        work_path = os.path.join(base_path, req_vals['normalized_branch'])

        data_file_path = os.path.dirname(BROKER_CONFIG_FILE)
        data_file_dir  = os.path.basename(data_file_path)
        data_file_name = os.path.basename(BROKER_CONFIG_FILE)
        tmpfs_path = '/mnt/data/tmpfs'
        filename = req_vals['build_url'].rsplit('/', 1)[1]

        result = None
        try:
                os.mkdir(work_path, mode=0o700)

                if req_vals['remote']:
                        dockerfile = 'Dockerfile.broker-runner'
                        file_path = os.path.join(work_path, filename)
                        r = requests.get(req_vals['build_url'], allow_redirects=True)
                        if not r:
                                raise RuntimeError('Failed to download build file')

                        open(file_path, 'wb').write(r.content)
                        open('{:s}.sha256'.format(file_path), 'w').write('{:s} {:s}'.format(req_vals['build_hash'], file_path))

                        # Validate checksum of file before untarring it. There is a module in python
                        # to do this, but I'm not going to read the whole file into memory to do it.
                        ret = subprocess.call(['sha256sum', '-c', '{:s}.sha256'.format(file_path)],
                                              stdout=subprocess.DEVNULL)
                        if ret:
                                raise RuntimeError('Failed to validate checksum of file')
                else:
                        dockerfile = 'Dockerfile.broker-localrunner'
                        file_path = req_vals['build_url'][7:]
                        shutil.copytree(file_path, os.path.join(work_path, filename))

                # Build new docker image from the base image, tagged with the normalized branch name
                # so that we can use/delete it more easily.
                try:
                        docker_client.images.build(tag=req_vals['normalized_branch'], path=work_path, rm=True,
                                                   dockerfile=os.path.join(base_path, dockerfile),
                                                   container_limits={'cpusetcpus': '{:d},{:d}'.format(
                                                           app.config['CPU_SET'][0], app.config['CPU_SET'][1])},
                                                   buildargs={'TMPFS_PATH': tmpfs_path,
                                                              'BUILD_FILE_NAME': filename})

                except docker.errors.BuildError as build_err:
                        app.logger.error(build_err)
                        raise RuntimeError('Failed to build runner image')

                log_output = ''

                if True:
#                for i in range(RUN_COUNT):
                        # Run benchmark
                        try:
                                # The docker API expects the seccomp to be the actual JSON from the file
                                # so trying to pass the filename fails (that works on the command-line).
                                # Load the json into a variable.
                                seccomp = open(os.path.join(base_path, 'zeek-seccomp.json'), 'r').read()

                                log_output += docker_client.containers.run(
                                        image=req_vals['normalized_branch'],
                                        remove=True, network='zeek-internal', cap_add=['SYS_NICE'],
                                        security_opt=['seccomp={:s}'.format(seccomp)],
                                        environment={
                                                'BUILD_FILE_NAME': filename,
                                                'DATA_FILE_PATH': data_file_path,
                                                'DATA_FILE_DIR' : data_file_dir,
                                                'DATA_FILE_NAME': data_file_name,
                                                'TMPFS_PATH': tmpfs_path},
                                        volumes={data_file_path: {'bind': data_file_path, 'mode': 'ro'}},
                                        tmpfs={tmpfs_path: ''},
                                        stderr=True).decode('utf-8','ignore')

                        except docker.errors.ContainerError as cont_err:
                                app.logger.error(cont_err)
                                raise RuntimeError('Runner failed')

                log_data = {}
                p = re.compile('zeek-recording-(.*?) \((.*?)\): (.*)s')
                for line in iter(log_output.splitlines()):
                        if line.startswith('system'):
                                parts = line.split(':')
                                log_data['system'] = float(parts[1].strip()[:-1])
                        else:
                                m = p.match(line)
                                if m:
                                        log_data['{:s}_{:s}'.format(m.group(1), m.group(2))] = float(m.group(3))

                db_conn = sqlite3.connect(DATABASE_FILE)
                c = db_conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS "broker" (
                                 "stamp" datetime primary key default (datetime('now', 'localtime')),
                                 "logger_sending" float not null,
                                 "logger_receiving" float not null,
                                 "manager_sending" float not null,
                                 "manager_receiving" float not null,
                                 "proxy_sending" float not null,
                                 "proxy_receiving" float not null,
                                 "worker_sending" float not null,
                                 "worker_receiving" float not null,
                                 "system" float not null);''')

                c.execute('''insert into broker (logger_sending, logger_receiving,
                                                 manager_sending, manager_receiving,
                                                 proxy_sending, proxy_receiving,
                                                 worker_sending, worker_receiving,
                                                 system) values (?,?,?,?,?,?,?,?,?)''',
                          [log_data['logger_sending'], log_data['logger_receiving'],
                           log_data['manager_sending'], log_data['manager_receiving'],
                           log_data['proxy_sending'], log_data['proxy_receiving'],
                           log_data['worker_sending'], log_data['worker_receiving'],
                           log_data['system']])

                db_conn.commit()
                db_conn.close()

        except RuntimeError as rt_err:
                app.logger.error(traceback.format_exc())
                result = (str(rt_err), 500)
        except:
                # log any other exceptions, but eat the string from them
                app.logger.error(traceback.format_exc())
                result = ('Failure occurred', 500)
        else:
                result = (log_output, 200)

        # Destroy the container and image
        try:
                docker_client.images.remove(image=req_vals['normalized_branch'], force=True)
        except docker.errors.APIError as api_err:
                app.logger.error(api_err)
                result = ('Failed to destroy runner image', 500)

        if os.path.exists(work_path):
                shutil.rmtree(work_path)

        return result

if __name__ == '__main__':
        app.run(host='127.0.0.1', port=8080, threaded=False)
