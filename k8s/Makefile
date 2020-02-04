GOFILES=`find . -type f -name '*.go'`

.PHONY: clean format template_test test render apply help docker-run

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

help:
	@echo "With this makefile you can clean, format, test, render, or apply the UAA K8s templates"

docker-run:
	docker pull cfidentity/uaa:latest \
	&& docker run --detach --publish 8080:8080 --env UAA_CONFIG_URL=classpath:required_configuration.yml --env spring_profiles=default,hsqldb cfidentity/uaa:latest

docker-debug:
	docker run --detach --publish 8080:8080 --publish 5005:5005 --env UAA_CONFIG_URL=classpath:required_configuration.yml --env spring_profiles=default,hsqldb --env JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Djava.security.egd=file:/dev/./urandom" cfidentity/uaa:latest
