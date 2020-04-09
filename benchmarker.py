import os
from flask import Flask
application = Flask(__name__)

@application.route("/")
def start():
        script_path = os.path.dirname(os.path.abspath(__file__))
        bench_path = os.path.join(script_path, 'build-and-bench.sh')
        bench_cmd = '{} {}'.format(bench_path, script_path)
        ret = os.system(bench_cmd)
        if ret:
                return "Bench script failed", 500

        log = None
        log_path = os.path.join(script_path, 'benchmark.log')
        with open(log_path, 'r') as log_file:
                log = log_file.read()

        if not log:
                return "Failed to read log file", 500

        return log, 200

if __name__ == "__main__":
	application.run(host="192.168.22.91")
