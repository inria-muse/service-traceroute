package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type InputPkt struct {
	Packet gopacket.Packet
}

type PcapHandler struct {
	BufferMb int
	SnapLen  int
	Filter   string
	Iface    string
	LocalV4  net.IP
	LocalV6  net.IP
	PktChan  chan InputPkt
	OutChan  chan string
	Done     chan bool
}

func (ph *PcapHandler) NewPacketHandler(cap CapThread, iface string, proto string, ip string, port int, pktChan chan InputPkt, outChan chan string, done chan bool) {
	ph.Iface = iface
	ph.SnapLen = cap.CapSize
	ph.BufferMb = cap.Buffer
	ph.Filter = cap.BPF
	ph.PktChan = pktChan
	ph.OutChan = outChan
	ph.Done = done

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
						if proto == V4 {
							validAddress = true
						}
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						ph.LocalV6 = (*v).IP
						if proto == V6 {
							fmt.Printf("Local V6 %s\n", v.IP.String())
							validAddress = true
						}
					}
				}
			}
		}
	}

	if !validAddress {
		log.Fatal("No valid IP for interface")
	}

	if ip != "" && cap.BPF != Icmp {
		ph.Filter += " and host " + ip
	}

	if port != 0 && cap.BPF != Icmp {
		ph.Filter += " and port " + fmt.Sprintf("%d", port)
	}
	fmt.Printf("Filters %s\n", ph.Filter)
}

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
		ph.Done <- true
		handle.Close()
	}()

	err = handle.SetBPFFilter(ph.Filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ph.PktChan <- InputPkt{Packet: packet}
	}
}
