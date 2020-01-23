GOFILES=`find . -type f -name '*.go'`

.PHONY: clean format test render apply help

clean:
	go clean

format:
	gofmt -l -s -w ${GOFILES}

test:
	go test -count=1 ./...

render:
	@ytt -f templates -f values/default-values.yml

apply:
	@ytt -f templates -f values/default-values.yml | kubectl apply -f -

help:
	@echo "With this makefile you can clean, format, test, render, or apply the UAA K8s templates"