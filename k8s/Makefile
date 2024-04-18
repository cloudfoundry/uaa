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
.PHONY: brew-cli

help:
	@echo "With this makefile you can clean, format, test, render, or apply the UAA K8s templates"

clean:
	go clean

format:
	gofmt -l -s -w ${GOFILES}

template_test:
	go version
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

brew-cli:
	brew install cloudfoundry/tap/uaa-cli
