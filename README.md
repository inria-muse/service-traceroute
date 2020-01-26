# Service Traceroute

*Service Traceroute* is a tool that allows the discovery of individual application flows paths. *Service Traceroute* leverages the ideas from [paratrace](http://www.adeptus-mechanicus.com/codex/paratrc/paratrc.php), [Sidecar](http://www.cs.umd.edu/projects/sidecar/), and [0trace](https://jon.oberheide.org/0trace/), to passively listen to application traffic to then issue traceroute probes that pretend to be part of the application flow. *Service Traceroute* extends this idea to work for modern Internet services and support tracing of multiple concurrent TCP flows, as well as for UDP flows. *Service Traceroute* is available both as command-line tool and library versions. Check out our [paper]() for more details on how *Service Traceroute* works.

To analyze the produced data, please refer to the following repository: [service-traceroute-analysis](https://github.com/inria-muse/service-traceroute-analysis).

### Installation from source code

*Service Traceroute* requires a working version of libpcap to be installed on your system. We have tested the code with the default version of libpcap distributed with Ubuntu 16.04, Fedora 25, and Mac OS High Sierra. The following instructions follow the steps used for Ubuntu, but should be easily adaptable to any other operating system.

To compile, first install eventual missing dependencies:

``
go get github.com/google/gopacket
``

Then retrieve the source code from this repository. You can easily do so by using go's built in management system:

``
go get github.com/inria-muse/service-traceroute
``

Change to the folder `$GOPATH/src/github.com/inria-muse/service-traceroute/`. (NOTE: this step assumes that you have set the `$GOPATH` environment variable. If you used the default value, this will correspond to `$HOME/go/`).

Then run:

``
./build.sh
``

This will create the `servicetraceroute-linux-amd64`. Build support for other architectures requires modifying the file `build.sh`

For help on how to execute a *Service Traceroute* experiment, run:

`./build/servicetraceroute-linux-amd64 -h`


### Installation from binary

Coming soon...

### Inclusion as a library in third party software

First, retrieve the source code from this repository:

``
go get github.com/inria-muse/service-traceroute
``

For an example of how to include a *Service Traceroute* experiment within a third party go program, please refer to the example found at: [https://github.com/inria-muse/service-traceroute/tree/master/example](https://github.com/inria-muse/service-traceroute/tree/master/example)

### Contacts
For any question, please contact us at [service-traceroute@inria.fr](mailto:service-traceroute@inria.fr)
