package servicetraceroute

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

//Structure of the sniffer
type PcapHandler struct {
	BufferMb int
	SnapLen  int
	Port     uint16
	Filter   string
	Iface    string
	LocalV4  net.IP
	LocalV6  net.IP
	PktChan  chan gopacket.Packet
	OutChan  chan string
	DoneChan chan bool
	StopChan chan bool

	Handler *pcap.Handle

	Ready chan bool
}

//Initialize and configure a new sniffer
func (ph *PcapHandler) NewPacketHandler(cap CapThread, iface string, ip string, pktChan chan gopacket.Packet, outChan chan string, ready chan bool) {
	ph.Iface = iface
	ph.SnapLen = cap.CapSize
	ph.BufferMb = cap.Buffer
	ph.Filter = cap.BPF
	ph.PktChan = pktChan
	ph.OutChan = outChan
	ph.Ready = ready
	ph.DoneChan = make(chan bool)
	ph.Port = cap.Port

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	validAddress := false

	for _, iface := range devices {
		if iface.Name == ph.Iface {
			netIface, err := net.InterfaceByName(ph.Iface)
			if err != nil {
				log.Fatal(err)
			}
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsGlobalUnicast() && v.IP.To4() != nil {
						ph.LocalV4 = (*v).IP
						validAddress = true
						// if proto == V4 {
						// 	validAddress = true
						// }
					} else if v.IP.To16() != nil {
						ph.LocalV6 = (*v).IP
						validAddress = true
						// if proto == V6 {
						// 	validAddress = true
						// }
					}
				}
			}
		}
	}

	if !validAddress {
		log.Fatal("No valid IP for interface")
	}

	if ip != "" {
		ph.Filter += " and host " + ip
	}

	if ph.Port != 0 {
		ph.Filter += " and port " + fmt.Sprintf("%d", ph.Port)
	}
}

//Run the sniffer on a specific interface and the filters given in input during the initialization
func (ph *PcapHandler) Run() {
	inactiveHandle, err := pcap.NewInactiveHandle(ph.Iface)
	if err != nil {
		log.Fatal(err)
	}

	inactiveHandle.SetSnapLen(ph.SnapLen)
	inactiveHandle.SetTimeout(pcap.BlockForever)
	inactiveHandle.SetBufferSize(1e6 * ph.BufferMb)

	handle, err := inactiveHandle.Activate()
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		handle.Close()
		ph.DoneChan <- true
	}()

	err = handle.SetBPFFilter(ph.Filter)
	if err != nil {
		log.Fatal(err)
	}

	ph.Handler = handle
	ph.Ready <- true

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ph.PktChan <- packet
	}
}

//Stop the sniffer
func (ph *PcapHandler) Stop() {
	ph.StopChan <- true
}
