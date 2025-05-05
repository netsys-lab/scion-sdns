package authcache

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Version type
type Version byte

const (
	// IPv4 mode
	IPv4 Version = 0x1

	// IPv6 mode
	IPv6 Version = 0x2

	// QUIC-SCION mode
	QUIC_SCION Version = 0x3
)

type CompoundServer struct {
	NsDomainName string
	/*ScionNs      []*AuthServer
	IPv6Ns       []*AuthServer
	IPv4Ns       []*AuthServer*/
	Instances map[Version][]*AuthServer
}

func (s *CompoundServer) Version() Version {
	if s.Instances == nil {
		return 0
	}

	if len(s.Instances[QUIC_SCION]) > 0 {
		return QUIC_SCION
	} else if len(s.Instances[IPv6]) > 0 {
		return IPv6
	} else if len(s.Instances[IPv4]) > 0 {
		return IPv4
	} else {
		return 0
	}

}

type AuthServer struct {
	// place atomic members at the start to fix alignment for ARM32
	Rtt          int64
	Count        int64
	Addr         string
	NsDomainName string // domain-name of the server (required for ServerName in TLSConfig and aggregation into CompoundServer for sort/filter-ing )
	Version      Version
}

// NewAuthServer return a new server
func NewAuthServer(addr string, version Version) *AuthServer {
	return &AuthServer{
		Addr:    addr,
		Version: version,
	}
}

func NewNamedAuthServer(servername, addr string, version Version) *AuthServer {
	return &AuthServer{
		Addr:         addr,
		Version:      version,
		NsDomainName: servername,
	}
}

func (v Version) String() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	case QUIC_SCION:
		return "QUIC-SCION"
	default:
		return "Unknown"
	}
}

func (a *AuthServer) String() string {
	count := atomic.LoadInt64(&a.Count)
	rn := atomic.LoadInt64(&a.Rtt)

	if count == 0 {
		count = 1
	}

	var health string
	if rn >= int64(time.Second) {
		health = "POOR"
	} else if rn > 0 {
		health = "GOOD"
	} else {
		health = "UNKNOWN"
	}

	rtt := (time.Duration(rn) / time.Duration(count)).Round(time.Millisecond)

	return a.Version.String() + ":" + a.Addr + " rtt:" + rtt.String() + " health:[" + health + "]"
}

// AuthServers type
type AuthServers struct {
	sync.RWMutex
	// place atomic members at the start to fix alignment for ARM32
	Called     uint64
	ErrorCount uint32

	Zone string

	List []*AuthServer
	Nss  []string

	CheckingDisable bool
	Checked         bool
}

/*
	 Sort sort servers first by version (scion-quic > ipv6>ipv4) then by rtt

		isolation: for a nameserver with name X:
		if X has a scion address, remove any IPv4/6 addresses it might also have
		(if we'd dial only one of a servers non-scion addresses, although it has a scion one,
		 we'd destroy any privacy gains, we actually seek)
		NOTE: this only works, if all AuthServers have their name set
		(i.e. they were constructed with NewNamedAuthServer() )

		\param enforceOnlyScion  discard any nameservers, that do not provide a scion address
*/
func SortAndIsolate(serversList []*AuthServer, called uint64, enforceOnlyScion bool) []*AuthServer {
	// var servers []CompoundServer
	var servers = make(map[string]CompoundServer)

	for _, s := range serversList {

		if cs, ok := servers[s.NsDomainName]; ok {
			// this name  has been encountered before, so only update additional instance
			instances := cs.Instances[s.Version]
			instances = append(instances, s) // might cause duplicates if serversList is not unique
			cs.Instances[s.Version] = instances
		} else {
			// new server name encountered in serversList
			c := CompoundServer{NsDomainName: s.NsDomainName}
			c.Instances = make(map[Version][]*AuthServer)
			c.Instances[s.Version] = append(c.Instances[s.Version], s)
			servers[s.NsDomainName] = c

		}

		//clear stats and re-start again
		if called%1e3 == 0 {
			atomic.StoreInt64(&s.Rtt, 0)
			atomic.StoreInt64(&s.Count, 0)

			continue
		}

		rtt := atomic.LoadInt64(&s.Rtt)
		count := atomic.LoadInt64(&s.Count)

		if count > 0 {
			// average rtt
			atomic.StoreInt64(&s.Rtt, rtt/count)
			atomic.StoreInt64(&s.Count, 1)
		}
	}

	//keys := make([]keyType, 0, len(myMap))
	values := make([]CompoundServer, 0, len(servers))

	for _, v := range servers {
		// keys = append(keys, k)
		values = append(values, v)
	}
	// sort candidate servers by version descendingly ( we want preferrably scion ones)
	sort.Slice(values, func(i, j int) bool { return values[i].Version() > values[j].Version() })

	var result []*AuthServer

	for _, v := range values {
		version := v.Version()
		if enforceOnlyScion {
			if version < QUIC_SCION {
				// values was sorted by version descendingly
				break
			}
		}
		servs := v.Instances[version]
		// now sort this candidates addresses by their Rtt
		sort.Slice(servs, func(i, j int) bool {

			rttLess := atomic.LoadInt64(&servs[i].Rtt) < atomic.LoadInt64(&servs[j].Rtt)
			return rttLess

		})
		// keep only the best
		result = append(result, servs[0])
		// result = append(result, servs...) // keep all but sorted by rtt

	}
	return result
}

// Sort sort servers first by version (scion-quic > ipv6>ipv4) then by rtt
func Sort(serversList []*AuthServer, called uint64) {
	for _, s := range serversList {
		//clear stats and re-start again
		if called%1e3 == 0 {
			atomic.StoreInt64(&s.Rtt, 0)
			atomic.StoreInt64(&s.Count, 0)

			continue
		}

		rtt := atomic.LoadInt64(&s.Rtt)
		count := atomic.LoadInt64(&s.Count)

		if count > 0 {
			// average rtt
			atomic.StoreInt64(&s.Rtt, rtt/count)
			atomic.StoreInt64(&s.Count, 1)
		}
	}
	sort.Slice(serversList, func(i, j int) bool {

		// higher version is better (ipv4<ipv6<scion_squic) and must compare less
		// in order for scion nameservers to preceede legacy ones
		versionLess := serversList[i].Version > serversList[j].Version
		sameversion := serversList[i].Version == serversList[j].Version

		if sameversion {
			rttLess := atomic.LoadInt64(&serversList[i].Rtt) < atomic.LoadInt64(&serversList[j].Rtt)
			return rttLess
		} else {
			return versionLess
		}

	})
}
