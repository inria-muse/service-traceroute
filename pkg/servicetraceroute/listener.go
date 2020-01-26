package servicetraceroute

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
)

//Class for managing the listeners of ServiceTracerouteManager
//It manages the sniffer for TCP, UDP, ICMP and DNS
//It is possible to use this class to start custom sniffers
type Listeners struct {
	pcapIDs       map[string]*PcapHandler //key: protocol.port.IP
	pcapUsedTimes map[string]int
	readyChan     chan bool
	mutex         *sync.Mutex //Mutex for offset array
	iface         string
	ipVersion     string
	outChan       chan string

	DefaultBuffer     int
	DefaultCapSize    int
	DefaultDNSBuffer  int
	DefaultDNSCapSize int

	DefaultUDP  CapThread
	DefaultTCP  CapThread
	DefaultICMP CapThread
	DefaultDNS  CapThread
}

//Configure a new instance of listeners
func (listeners *Listeners) NewListeners(iface string, outChan chan string) {
	listeners.pcapIDs = make(map[string]*PcapHandler)
	listeners.pcapUsedTimes = make(map[string]int)
	listeners.readyChan = make(chan bool)
	listeners.mutex = &sync.Mutex{}

	listeners.iface = iface
	listeners.outChan = outChan

	listeners.DefaultDNSBuffer = 10
	listeners.DefaultDNSCapSize = 1500

	listeners.DefaultBuffer = 100
	listeners.DefaultCapSize = 100

	listeners.DefaultICMP = CapThread{
		BPF:     Icmp,
		Buffer:  listeners.DefaultBuffer,
		CapSize: listeners.DefaultCapSize,
		Port:    0,
		IP:      "",
	}

	listeners.DefaultTCP = CapThread{
		BPF:     Tcp,
		Buffer:  listeners.DefaultBuffer,
		CapSize: listeners.DefaultCapSize,
		Port:    443,
		IP:      "",
	}

	listeners.DefaultUDP = CapThread{
		BPF:     Udp,
		Buffer:  listeners.DefaultBuffer,
		CapSize: listeners.DefaultCapSize,
		Port:    0,
		IP:      "",
	}

	listeners.DefaultDNS = CapThread{
		BPF:     Udp,
		Buffer:  listeners.DefaultDNSBuffer,
		CapSize: listeners.DefaultDNSCapSize,
		Port:    53,
		IP:      "",
	}
}

//Start a customized listener which is configured through the struct CapThread
func (listeners *Listeners) StartCustomizedListener(cap CapThread, outPktChan chan gopacket.Packet) {
	listeners.mutex.Lock()
	host := cap.IP
	if host == "" {
		host = "none"
	}
	key := fmt.Sprintf("%s.%d.%s", cap.BPF, cap.Port, host)

	//Start only if there are no handlers listening the same packets
	if _, alive := listeners.pcapIDs[key]; !alive {
		pcap := new(PcapHandler)
		pcap.NewPacketHandler(cap, listeners.iface, cap.IP, outPktChan, listeners.outChan, listeners.readyChan)
		go pcap.Run()
		<-listeners.readyChan

		listeners.pcapIDs[key] = pcap
		listeners.pcapUsedTimes[key] = 0
	}
	listeners.pcapUsedTimes[key]++

	listeners.mutex.Unlock()
}

//Stop and close a specific customized listener
func (listeners *Listeners) StopCustomizedListener(cap CapThread) {
	listeners.mutex.Lock()
	key := fmt.Sprintf("%s-%d", cap.BPF, cap.Port)

	if pcap, ok := listeners.pcapIDs[key]; ok {
		listeners.pcapUsedTimes[key]--

		if listeners.pcapUsedTimes[key] <= 0 {
			pcap.Stop()
			<-pcap.DoneChan
			delete(listeners.pcapIDs, key)
			delete(listeners.pcapUsedTimes, key)
		}
	}
	listeners.mutex.Unlock()
}

//Start a TCP sniffer with default values of Listeners.
//It relies on StartCustomizedListener to start a new sniffer
func (listeners *Listeners) StartTCP(outPktChan chan gopacket.Packet) {
	listeners.StartCustomizedListener(listeners.DefaultTCP, outPktChan)
}

//Start a UDP sniffer with default values of Listeners.
//It relies on StartCustomizedListener to start a new sniffer
func (listeners *Listeners) StartUDP(outPktChan chan gopacket.Packet) {
	listeners.StartCustomizedListener(listeners.DefaultUDP, outPktChan)
}

//Start a ICMP sniffer with default values of Listeners.
//It relies on StartCustomizedListener to start a new sniffer
func (listeners *Listeners) StartICMP(outPktChan chan gopacket.Packet) {
	listeners.StartCustomizedListener(listeners.DefaultICMP, outPktChan)
}

//Start a DNS sniffer with default values of Listeners.
//It relies on StartCustomizedListener to start a new sniffer
func (listeners *Listeners) StartDNS(outPktChan chan gopacket.Packet) {
	listeners.StartCustomizedListener(listeners.DefaultDNS, outPktChan)
}

//Stop and close a TCP sniffer with default values of Listeners.
//It relies on StopCustomizedListener to start a new sniffer
func (listeners *Listeners) StopTCP() {
	listeners.StopCustomizedListener(listeners.DefaultTCP)
}

//Stop and close a UDP sniffer with default values of Listeners.
//It relies on StopCustomizedListener to start a new sniffer
func (listeners *Listeners) StoptUDP() {
	listeners.StopCustomizedListener(listeners.DefaultUDP)
}

//Stop and close a ICMP sniffer with default values of Listeners.
//It relies on StopCustomizedListener to start a new sniffer
func (listeners *Listeners) StoptICMP() {
	listeners.StopCustomizedListener(listeners.DefaultICMP)
}

//Stop and close a DNS sniffer with default values of Listeners.
//It relies on StopCustomizedListener to start a new sniffer
func (listeners *Listeners) StopDNS() {
	listeners.StopCustomizedListener(listeners.DefaultDNS)
}
