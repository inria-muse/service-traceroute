BIN= $(shell basename $$PWD)
GP= $(shell dirname $(shell dirname $$PWD))

all:	export GOPATH=$(GP)
all:	*.go
	go build -v $(BIN)
clean:
	rm $(BIN)
