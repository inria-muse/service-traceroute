package main

import (
	"errors"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"
)

const Unknown = "Unknown"
const Other = "Other"

const (
	Video uint8 = 0
	Ads   uint8 = 1
	None  uint8 = 2
)

const (
	QUICHeaderLen      = 100 //B
	ChunkStdDeviations = 5
	ChunkIATMin        = 50 //ms
	CongestionIATMin   = 50 //ms
	CongestionMinPkts  = 10
	CongestionNAvg     = 2
)

type CName struct {
	Expire int64
}

type IpMap struct {
	Name     string
	Domain   string
	Type     uint8
	Expire   int64
	LastUsed int64
}

type Service struct {
	Name          string
	DomainsString []string
	DomainsRegex  []string
	ServiceType   uint8
	StringMatch   *AhoCorasick
	Regexps       []*regexp.Regexp
	CNames        map[string]CName
	Prefixes      []string
	PrefixNets    []*net.IPNet
}

type TrafficStats struct {
	Services []Service
	IpLookup map[string]IpMap
	LastPkt  int64

	MapMutex *sync.Mutex
}

func (ts *TrafficStats) NewTrafficStats(services []Service) {
	ts.Services = services
	ts.IpLookup = map[string]IpMap{}
	ts.MapMutex = &sync.Mutex{}

	for i, s := range ts.Services {
		ts.Services[i].StringMatch = new(AhoCorasick)
		ts.Services[i].StringMatch.NewAhoCorasick()
		for _, ds := range s.DomainsString {
			ts.Services[i].StringMatch.AddString(ds, ds)
		}
		ts.Services[i].StringMatch.Failure()

		ts.Services[i].Regexps = []*regexp.Regexp{}
		for _, dr := range s.DomainsRegex {
			if r, err := regexp.Compile(dr); err == nil {
				ts.Services[i].Regexps = append(ts.Services[i].Regexps, r)
			} else {
				panic("Could not compile " + dr + " " + err.Error())
			}
		}

		for _, p := range s.Prefixes {
			if _, n, err := net.ParseCIDR(p); err == nil {
				ts.Services[i].PrefixNets = append(ts.Services[i].PrefixNets, n)
			} else {
				panic("Could not parse prefix " + p + " " + err.Error())
			}
		}

		ts.Services[i].CNames = make(map[string]CName)
	}
}

func (ts *TrafficStats) ParseDnsResponse(dns layers.DNS, pTs int64) {
	sName := Other
	dName := ""
	sType := None
	var sId int
	var s Service

	for _, q := range dns.Questions[:1] { // Assuming there's only one query.
		for sId, s = range ts.Services {
			acMatch := s.StringMatch.FirstMatch(string(q.Name))
			if len(acMatch) > 0 {
				sName = s.Name
				dName = acMatch[0]
				sType = s.ServiceType
				break
			}

			for _, r := range s.Regexps {
				if r.MatchString(string(q.Name)) {
					sName = s.Name
					dName = r.String()
					sType = s.ServiceType
					break
				}
			}
			if sName != Other {
				break
			}

			if _, ok := s.CNames[string(q.Name)]; ok == true { // Don't check CNAME TTL for now
				sName = s.Name
				dName = string(q.Name)
				sType = s.ServiceType
				break
			}
		}
	}

	for _, a := range dns.Answers {
		if sName != Other && a.CNAME != nil {
			s := ts.Services[sId]
			cn := string(a.CNAME)
			if c, t := s.CNames[cn]; t == true {
				c.Expire = pTs + int64(a.TTL)
				s.CNames[cn] = c
			} else {
				s.CNames[cn] = CName{Expire: pTs + int64(a.TTL)}
			}
		}
		if a.IP != nil {
			ts.MapMutex.Lock()
			ts.IpLookup[a.IP.String()] = IpMap{Name: sName, Domain: dName, Type: sType, Expire: pTs + int64(a.TTL), LastUsed: pTs}
			ts.MapMutex.Unlock()
		}
	}

}

func (ts *TrafficStats) ParseDnsLayer(pkt gopacket.Packet) error {
	ts.ClearDnsCache()
	dnsLayer := (pkt).Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return errors.New("not a DNS pkt")
	}
	dns, _ := dnsLayer.(*layers.DNS)
	ts.ParseDnsResponse(*dns, (pkt).Metadata().Timestamp.Unix())
	return nil
}

func (ts *TrafficStats) ClearDnsCache() {
	ts.MapMutex.Lock()
	now := time.Now().Unix()
	for i, d := range ts.IpLookup {
		if d.Expire < now && d.LastUsed+600 < now { // delete only if expired AND the IP hasn't been seen in 10 min
			delete(ts.IpLookup, i)
		}
	}
	ts.MapMutex.Unlock()
}
