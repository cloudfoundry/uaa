GOFILES=`find . -type f -name '*.go'`

.PHONY: help clean format template_test test render apply minikube docker-run docker-debug

help:
	@echo "With this makefile you can clean, format, test, render, or apply the UAA K8s templates"

clean:
	go clean

format:
	gofmt -l -s -w ${GOFILES}

template_test:
	go test -count=1 ./test/...

test: format template_test

render:
	@ytt -f templates

apply:
	@ytt -f templates | kubectl apply -f -

minikube:
	@ytt -f templates -f addons | kubectl apply -f -

docker-run:
	docker pull cfidentity/uaa:latest \
	&& docker run \
		--detach \
		--publish 8080:8080 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=default,hsqldb \
		cfidentity/uaa:latest

docker-debug:
	docker run \
		--detach \
		--publish 8080:8080 \
		--publish 5005:5005 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=default,hsqldb \
		--env JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Djava.security.egd=file:/dev/./urandom" \
		cfidentity/uaa:latest
