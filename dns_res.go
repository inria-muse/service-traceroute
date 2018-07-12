package tracetcp

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"
)

//Json structure contained in the configuration file
type InJson struct {
	Services []Service
}

const Unknown = "Unknown"
const Other = "Other"

const (
	Video uint8 = 0
	Ads   uint8 = 1
	None  uint8 = 2
)

//Structures used for the DNS resolution
type CName struct {
	Expire int64
}

//Map one IP to a specific service
type IpMap struct {
	Name     string
	Domain   string
	Type     uint8
	Expire   int64
	LastUsed int64
}

//Map one IP to a set of services with the relative resolution address
type ServiceMap struct {
	Names         []string
	IPResolutions []string
	Expire        int64
	LastUsed      int64
}

//Structure to identify the DNS request to one service
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

//DNS resolver containing the detected DNS requests/responses
type DNSResolver struct {
	Services      []Service
	IpLookup      map[string]IpMap
	ServiceLookup map[string]ServiceMap
	LastPkt       int64

	DNSChan  chan gopacket.Packet
	StopChan chan bool
	MapMutex *sync.Mutex
}

//Initialize the DNS resolver loading the configuration from the filename and the input packets through the DNSChan
func (ts *DNSResolver) NewDNSResolver(filename string, DNSChan chan gopacket.Packet) {
	ts.LoadServices(filename)
	ts.IpLookup = map[string]IpMap{}
	ts.ServiceLookup = map[string]ServiceMap{}
	ts.StopChan = make(chan bool)
	ts.MapMutex = &sync.Mutex{}
	ts.DNSChan = DNSChan
	ts.ComputeServices()
}

//Updates the services when one service is added
func (ts *DNSResolver) UpdateService(service ServiceConfiguration) {
	ts.MapMutex.Lock()
	modified := false
	for _, s := range ts.Services {
		if strings.ToLower(s.Name) == strings.ToLower(service.Service) && s.ServiceType == service.ServiceType {
			if service.URLs != nil {
				s.DomainsString = append(s.DomainsString, service.URLs...)
			}
			if service.IPPrefixes != nil {
				s.Prefixes = append(s.Prefixes, service.IPPrefixes...)
			}
			modified = true
			break
		}
	}
	s := Service{
		Name:          service.Service,
		ServiceType:   service.ServiceType,
		DomainsString: service.URLs,
		Prefixes:      service.IPPrefixes,
	}
	if !modified {
		ts.Services = append(ts.Services, s)
	}

	ts.ComputeServices()
	ts.MapMutex.Unlock()
}

//Build the string matching graph of AHO Corasick
func (ts *DNSResolver) ComputeServices() {
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

//Load the configuration from a file
func (ts *DNSResolver) LoadServices(filename string) {
	inputF := filename
	conf := InJson{}
	if sf, err := ioutil.ReadFile(inputF); err == nil {
		if err = json.Unmarshal(sf, &conf); err != nil {
			panic("Error reading " + inputF + " : " + err.Error())
		}
	} else {
		panic(inputF + " could not be found.")
	}
	ts.Services = conf.Services
}

//Parse the DNS response to find the requests and responses
func (ts *DNSResolver) ParseDnsResponse(dns layers.DNS, pTs int64) {
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
			ts.IpLookup[a.IP.String()] = IpMap{Name: sName, Domain: dName, Type: sType, Expire: pTs + int64(a.TTL), LastUsed: pTs}
		}
	}
}

//Parse the DNS response to find the requests and responses and find all services associated to an IP
func (ts *DNSResolver) UpdateServiceLookup(dns layers.DNS, pTs int64) {
	sName := Other
	rName := ""
	var sId int
	var s Service

	services := make([]string, 0)
	ipresolutions := make([]string, 0)

	for sId, s = range ts.Services {
		sName = Other
		for _, q := range dns.Questions[:1] {
			acMatch := s.StringMatch.FirstMatch(string(q.Name))
			rName = string(q.Name)
			if len(acMatch) > 0 {
				sName = s.Name
			}
			for _, r := range s.Regexps {
				if r.MatchString(string(q.Name)) {
					sName = s.Name
					break
				}
			}
			if _, ok := s.CNames[string(q.Name)]; ok == true { // Don't check CNAME TTL for now
				sName = s.Name
				break
			}
		}
		if sName != Other {
			services = append(services, sName)
			ipresolutions = append(ipresolutions, rName)
		}
	}
	if len(services) <= 0 {
		services = append(services, Other)
		ipresolutions = append(ipresolutions, "")
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
			ts.ServiceLookup[a.IP.String()] = ServiceMap{Names: services, IPResolutions: ipresolutions, Expire: pTs + int64(a.TTL), LastUsed: pTs}
		}
	}
}

//Parse the DNS request
func (ts *DNSResolver) ParseDnsLayer(pkt gopacket.Packet) error {
	ts.ClearDnsCache()
	ts.MapMutex.Lock()
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		ts.MapMutex.Unlock()
		return errors.New("not a DNS pkt")
	}
	dns, _ := dnsLayer.(*layers.DNS)
	//This function map 1 IP to 1 service
	// ts.ParseDnsResponse(*dns, pkt.Metadata().Timestamp.Unix())
	//So in this case we use UpdateServiceLookup which associate all services of 1 IP
	//Since more services may share the same URLs/IPs
	ts.UpdateServiceLookup(*dns, pkt.Metadata().Timestamp.Unix())
	ts.MapMutex.Unlock()
	return nil
}

//Remove all the DNS records not update from a while
func (ts *DNSResolver) ClearDnsCache() {
	ts.MapMutex.Lock()
	now := time.Now().Unix()
	for i, d := range ts.IpLookup {
		if d.Expire < now && d.LastUsed+600 < now { // delete only if expired AND the IP hasn't been seen in 10 min
			delete(ts.IpLookup, i)
		}
	}
	ts.MapMutex.Unlock()
}

//Given an IP it returns the resolution address corresponding to the IP
func (ts *DNSResolver) ResolveIP(ip net.IP) (ServiceMap, error) {
	resolution := ServiceMap{}
	err := errors.New("IP not resolved")

	ts.MapMutex.Lock()
	if res, ok := ts.ServiceLookup[ip.String()]; ok {
		resolution = res
		err = nil
	}
	ts.MapMutex.Unlock()
	return resolution, err
}

//Run the listener on the incoming DNS packets to be analyzed
func (ts *DNSResolver) Run() {
	for {
		select {
		case <-ts.StopChan:
			return
		case dsnPkt := <-ts.DNSChan:
			err := ts.ParseDnsLayer(dsnPkt)
			if err != nil {
				println(err.Error())
			}
		}
	}
}

//Stop the DNS resolver
func (ts *DNSResolver) Stop() {
	ts.StopChan <- true
}
