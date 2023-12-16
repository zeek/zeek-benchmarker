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

.PHONY:
prepare-local-testing: zeek-benchmarker-zeek-runner
	mkdir -p ./persistent
	mkdir -p ./testing/builds
	for v in test_data broker_test_data zeek_install_data app_spool_data ; do \
		mkdir -p $$(pwd)/testing/volumes/$${v} ; \
		docker volume create --driver local --opt type=none --opt device=$$(pwd)/testing/volumes/$${v} --opt o=bind $${v} ; \
	done
