# Development Notes

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
