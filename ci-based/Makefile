all: zeek-benchmarker-zeek-runner


.PHONY:
zeek-benchmarker-zeek-runner:
	docker build -f Dockerfile . -t $@

.PHONY:
up:
	docker-compose up --force-recreate -d

.PHONY:
tail-logs:
	docker-compose logs --follow --tail=100
