Notes on Development
====================

Running the benchmarker via `flask run`

    FLASK_APP=benchmarker.py flask run --reload -p 8080


Use python3 client.py to submit builds to the locally running benchmarker API:

    python3 client.py mybranch \
        --build-url http://localhost:8000/builds/5721034205167616/build.tgz \
        --build-hash d3de665720ed5e752275269d3fca62a0696700a6e61306fc392f1514b2083da7


The build.tgz in above example hosted locally and served by `python3 -m http.server`
running in a directory with the following layout:

    .
    ├── builds
    │   └── 5721034205167616
    │       └── build.tgz

## Running the rq worker

  npx nodemon -e py -w ./zeek_benchmarker/ --exec rq worker -- -c settings


## Within the container

* task.job_dir is mounted at /benchmarker/binaries

* That is where build.tgz is located

* run-zeek.sh will unpack the tgz into /benchmarker
  * Location of binary in container: /benchmarker/zeek/install/bin/zeek
  * This is not the configured path
