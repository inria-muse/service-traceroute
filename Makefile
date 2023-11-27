all:
	go build -o servicetraceroute cmd/servicetraceroute/servicetraceroute.go

clean:
	rm -f servicetraceroute