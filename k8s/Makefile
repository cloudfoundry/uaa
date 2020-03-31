GOFILES=`find . -type f -name '*.go'`

.PHONY: help
.PHONY: clean
.PHONY: format
.PHONY: template_test
.PHONY: test
.PHONY: render
.PHONY: apply
.PHONY: kubectl-clean
.PHONY: kubectl-clean-all
.PHONY: docker-run
.PHONY: docker-debug
.PHONY: brew-cli

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

kubectl-clean:
	kubectl delete deployments,services,secrets,replicasets,services,pods,configmaps,serviceaccounts --all

kubectl-clean-all:
	kubectl delete all,ingress --all

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

brew-cli:
	brew install cloudfoundry/tap/uaa-cli
