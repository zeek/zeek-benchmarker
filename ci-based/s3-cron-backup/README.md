# Backup

docker-compose setup for backing up the persistent SQLite database as well
as Grafana's database.

Based on [peterrus/docker-s3-cron-backup](https://github.com/peterrus/docker-s3-cron-backup).


## Instructions

Put `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in a `.env` file within
this directory.

Run `docker-compose up -d`. Verify.
