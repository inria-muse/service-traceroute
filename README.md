# Service Traceroute

*Service Traceroute* is a tool that allows the discovery of individual application flows paths. *Service Traceroute* leverages the ideas from [paratrace](http://www.adeptus-mechanicus.com/codex/paratrc/paratrc.php), [Sidecar](http://www.cs.umd.edu/projects/sidecar/), and [0trace](https://jon.oberheide.org/0trace/), to passively listen to application traffic to then issue traceroute probes that pretend to be part of the application flow. *Service Traceroute* extends this idea to work for modern Internet services and support tracing of multiple concurrent TCP flows, as well as for UDP flows. *Service Traceroute* is available both as command-line tool and library versions. Check out our [paper]() for more details.

## Installation instructions

*Service Traceroute* is available both as command-line tool and library versions. The following instructions explain how to install each version.

### Installation from binary

Install the required 
