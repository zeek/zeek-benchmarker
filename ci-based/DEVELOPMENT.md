# Development Notes

## Running locally

Running `make up` will build all required container images and
start the services declared in the `docker-compose.yml` file.

### test-http

The docker-compose environment declares a `test-http` service that can be
used for local development. All files located in `./testing/builds` can be
fetched from the `test-http` service within the docker-compose environment.

With the following directory structure `./testing`, the benchmarker API can
be instructed to use `http://test-http:8000/builds/zeek/build-5.2.tgz` as
the build URL. In a production environment, the build URL points at Cirrus.

    ./testing
    └── builds
        └── zeek
            └── build-5.2.tgz

### Submitting a Benchmarking Job

To submit a Zeek benchmarking job with branch release/5.2, use the `tools/client.py`
utility. It defaults to an `HMAC_KEY` of `unset`, so it should just work unless
the `config.yml` was changed.

    python3 tools/client.py zeek release/5.2 \
        --api-url http://localhost:8080 \
        --build-hash 41ffacd82b02c923d53b675b113ec3bb55d320538c2c0cfb71c575a4cdb71371 \
        --build-url http://test-http:8000//builds/zeek/build-5.2.tgz \
        --cirrus-task-name ubuntu22
    {'job': {'enqueued_at': 'Tue, 10 Oct 2023 14:03:46 GMT', 'id': 'e23f8194-1aa4-40ab-a92c-5eddf0e1bf8e'}}

If you're running `make tail-logs` in a separate terminal, logs should be
produced indicating progress.

It is possible to use `tools/client.py` to re-submit jobs to the production API.
This requires of the correct HMAC key and only works with build artifacts already
and still stored by Cirrus.

## Database Migrations

This project is using [Alembic](https://alembic.sqlalchemy.org/en/latest/)
for dealing with database migrations.

### Initializing a database

To initialize a new database, update the `sqlalchemy.url` setting in the
`alembic.ini` file to the database file you want to use (default is `persistent/metrics2.db`).
Then run the following command to apply all migrations:

    # alembic upgrade head

### Creating a new Migration

To modify the current database schema to add a table or column, use `alembic revision`:

    # $ alembic revision -m 'add machine table'
    Generating /<...>/alembic/versions/20230928_1204-311be9937d3e_add_machine_table.py ...  done

Now, edit the generated file in the `alembic/versions/` directory. Specifically,
fill out the `upgrade()` and `downgrade()` methods. The existing migrations provide
examples.
The [Alembic tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html#create-a-migration-script) may be useful too.


To test the migration, run `upgrade` against the database

    # alembic upgrade head

To test the `downgrade()` method, revert to the prior version using `downgrade`:

    # alembic downgrade -1  (or use the previous revision identifier explicitly)

### Deploying a Migration

When deploying code that expects a newer database schema, the current process
is to manually run `alembic upgrade head` before restarting the docker-compose
managed services.
