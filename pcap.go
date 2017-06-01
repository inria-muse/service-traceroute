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
	BufferMb   int
	SnapLen    int
	Filter     string
	Iface      string
	LocalNetv4 net.IPNet
	LocalNetv6 net.IPNet
	PktChan    chan InputPkt
	OutChan    chan string
	Done       chan bool
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
		panic(err)
	}

	if cap.Dir == In {
		ph.Filter += " and dst "
	} else {
		ph.Filter += " and src "
	}

	validAddress := false

	for _, iface := range devices {
		if iface.Name == ph.Iface {
			netIface, err := net.InterfaceByName(ph.Iface)
			if err != nil {
				panic(err)
			}
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsGlobalUnicast() && v.IP.To4() != nil {
						ph.LocalNetv4 = *v
						ph.Filter += (*v).IP.String()
						if proto == V4 {
							validAddress = true
						}
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						ph.LocalNetv6 = *v
						ph.Filter += (*v).IP.String()
						if proto == V6 {
							validAddress = true
						}
					}
				}
			}
		}
	}

	if !validAddress {
		panic("No valid IP for interface")
	}

	if port != 0 {
		ph.Filter += " and port " + fmt.Sprintf("%d", port)
	}

	if ip != "" {
		if cap.Dir == In {
			ph.Filter += " and src " + ip
		} else {
			ph.Filter += " and dst " + ip
		}
	}
}

func (ph *PcapHandler) Run() {
	inactiveHandle, err := pcap.NewInactiveHandle(ph.Iface)
	if err != nil {
		log.Fatal(err)
	}

	inactiveHandle.SetSnapLen(ph.SnapLen)
	inactiveHandle.SetTimeout(pcap.BlockForever)
	inactiveHandle.SetBufferSize(1000000 * ph.BufferMb)

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
