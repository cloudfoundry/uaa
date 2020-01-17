GOFILES=`find . -type f -name '*.go'`

.PHONY: clean
clean:
	go clean

.PHONY: format
format:
	gofmt -l -s -w ${GOFILES}

.PHONY: test
test:
	go test -count=1 ./...

.PHONY: render
render:
	@ytt -f templates -f values/default-values.yml -f values/custom-values.yml

