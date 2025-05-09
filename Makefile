progs= trinctool

# this is so sudo can find the go binary
GO=/usr/local/go/bin/go

all: $(progs)

$(progs): % : vet
	$(GO) build ./cmd/$@

vet: fmt
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

test: vet
	sudo $(GO) test -v -count=1 -cover

benchmark: vet
	sudo $(GO) test -v -bench=. -benchmem

clean:
	rm -f $(progs)

.PHONY: all vet fmt clean
