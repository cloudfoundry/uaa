GOFILES=`find . -type f -name '*.go'`

.PHONY: help
.PHONY: clean
.PHONY: format
.PHONY: template_test
.PHONY: test
.PHONY: render
.PHONY: apply
.PHONY: minikube
.PHONY: kubectl-clean
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

apply-dev:
	@ytt -f templates -f addons -v include_default_profile=true | kubectl apply -f -

start-cluster:
	./scripts/minikube-init.sh

clean-cluster:
	kubectl delete all,ingress --all

docker-run:
	./scripts/docker-run.sh cfidentity/uaa:latest ${PWD}/../scripts/cargo/uaa.yml

docker-debug:
	./scripts/docker-run.sh -d cfidentity/uaa:latest ${PWD}/../scripts/cargo/uaa.yml
