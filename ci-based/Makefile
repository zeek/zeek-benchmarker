all: zeek-benchmarker-zeek-runner docker-compose-build


.PHONY:
zeek-benchmarker-zeek-runner:
	docker build -f Dockerfile . -t $@

.PHONY:
docker-compose-build:
	docker-compose build

.PHONY:
up: all
	docker-compose up --force-recreate -d

.PHONY:
down:
	docker-compose down

.PHONY:
tail-logs:
	docker-compose logs --follow --tail=100
