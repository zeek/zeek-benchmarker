FROM debian:12@sha256:b4042f895d5d1f8df415caebe7c416f9dbcf0dc8867abb225955006de50b21f3

RUN apt-get update && apt-get install -y --no-install-recommends \
	python3 \
	python3-pip \
	python3-venv \
	docker.io \
	docker-compose \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python3 -m venv .venv

COPY requirements.txt .

RUN .venv/bin/pip install --break-system-packages -r requirements.txt

COPY ./zeek_benchmarker ./zeek_benchmarker
