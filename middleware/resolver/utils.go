package resolver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/semihalev/log"
)

var (
	errNoDNSKEY               = errors.New("no DNSKEY records found")
	errMissingKSK             = errors.New("no KSK DNSKEY found for DS records")
	errFailedToConvertKSK     = errors.New("failed to convert KSK DNSKEY record to DS record")
	errMismatchingDS          = errors.New("KSK DNSKEY record does not match DS record from parent zone")
	errNoSignatures           = errors.New("no RRSIG records for zone that should be signed")
	errMissingDNSKEY          = errors.New("no matching DNSKEY found for RRSIG records")
	errInvalidSignaturePeriod = errors.New("incorrect signature validity period")
	errMissingSigned          = errors.New("signed records are missing")
	errNoROA                  = errors.New("no complete ROA records found")

	localIPaddrs []net.IP
)

func init() {
	rand.Seed(time.Now().UnixNano())

	var err error
	localIPaddrs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Find local ip addresses failed", "error", err.Error())
	}
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

func shuffleStr(vals []string) []string {
	perm := rand.Perm(len(vals))
	ret := make([]string, len(vals))

	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
	}

	return ret
}

/*
search the response msg's Answer section and return any addresses A,AAAA, TXT from it
*/
func searchAddrs(msg *dns.Msg) (addrs []string, found bool) {
	found = false

	for _, rr := range msg.Answer {
		if r, ok := rr.(*dns.A); ok {
			if isLocalIP(r.A) {
				continue
			}

			if r.A.To4() == nil {
				continue
			}

			if r.A.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.A.String())
			found = true
		} else if r, ok := rr.(*dns.AAAA); ok {
			if isLocalIP(r.AAAA) {
				continue
			}

			if r.AAAA.To16() == nil {
				continue
			}

			if r.AAAA.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.AAAA.String())
			found = true
		} else if r, ok := rr.(*dns.TXT); ok {
			///if saddr := SCIONAddrFromString(strings.Join(r.Txt), ""); saddr != "" {		}
			//}

			if saddr, okk := parseTXTasSCIONAddr(r); okk {
				addrs = append(addrs, saddr)
				found = true
			}
		}
	}

	return
}

func findLocalIPAddresses() ([]net.IP, error) {
	var list []net.IP
	tt, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, t := range tt {
		aa, err := t.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range aa {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			list = append(list, ipnet.IP)
		}
	}

	return list, nil
}

func getIPAddressFromScionTXT(txt *dns.TXT) net.IP {
	content := strings.Join(txt.Txt, "")
	addrstr := strings.SplitAfter(content, ",")[1]
	addr := parseIPv4(addrstr)
	return addr
}

/*
	 takes a TXT record with a scion address like:
		; dummy domain
		dummy    IN   TXT 'scion=19-ffaa:1:1067,127.0.0.2'

		and returns the contained scion address without the scion= prefix

		If the TXT-RR has no 'scion=' prefix, we double check whether its not a scion address after all
*/
func parseTXTasSCIONAddr(txt *dns.TXT) (addr string, ok bool) {
	content := strings.Join(txt.Txt, "")
	keyvalue := strings.Split(content, "=")
	if strings.ToLower(keyvalue[0]) == "scion" && len(keyvalue) == 2 {
		tokens := strings.SplitAfter(keyvalue[1], ",")
		if len(tokens) == 2 {
			addr = tokens[0] + "[" + tokens[1] + "]"
			ok = true
		}
	} else {
		scadd := SCIONAddrFromString(content)
		if _, k := pan.ParseUDPAddr(scadd); k == nil {
			return scadd, true
			// return ad.String() // that is somehow broken: 19-ffaa:1:1067,[127.0.0.1]:10000 becomes 19-ffaa:1:1067,127.0.0.1:10000
		} else {
			return
		}
	}
	return
}

func HasPort(addr string) bool {
	addrRegexp := regexp.MustCompile(`(?P<isia>\d+-[\d:A-Fa-f]+,[\d.:\[\]a-z]+):(?P<port>\d+)`)

	match := addrRegexp.FindStringSubmatch(addr)

	return len(match) == 2

}

func WithPortIfNotSet(addr string, port int) string {
	addrRegexp := regexp.MustCompile(`(?P<isia>\d+-[\d:A-Fa-f]+,[\d.:\[\]a-z]+):(?P<port>\d+)`)

	match := addrRegexp.FindStringSubmatch(addr)

	if len(match) == 3 {
		// address already has port
		return match[0]
	}
	return match[1] + ":" + fmt.Sprint(port)
}

/*
extract a SCION address from a string i.E.:
"'19-ffaa:1:1094,[127.0.0.1]'" => "19-ffaa:1.1094,[127.0.0.1]"

"scion=19-ffaa:1:1067,[127.0.0.1]" => 19-ffaa:1:1067,[127.0.0.1]
return empty-string if not found
*/
func SCIONAddrFromString(addr string) string {
	addrRegexp := regexp.MustCompile(`(?P<ia>\d+-[\d:A-Fa-f]+),(?P<host>[\d.:\[\]a-z]+)`)

	match := addrRegexp.FindStringSubmatch(addr)
	if len(match) != 3 {
		return "" // serrors.New("invalid address: regex match failed", "addr", s)
	}
	left, right := strings.Count(addr, "["), strings.Count(addr, "]")
	if left != right {
		return "" // serrors.New("invalid address: bracket count mismatch", "addr", s)
	}
	if strings.HasSuffix(match[2], ":") {
		return "" // ,  serrors.New("invalid address: trailing ':'", "addr", s)
	}
	return match[1] + "," + match[2]
}

func parseIPv4(s string) net.IP {
	var p [net.IPv4len]byte
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		if c > 1 && s[0] == '0' {
			// Reject non-zero components with leading zeroes.
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return net.IPv4(p[0], p[1], p[2], p[3])
}

const big = 0xFFFFFF

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

func isLocalIP(ip net.IP) (ok bool) {
	for _, l := range localIPaddrs {
		if ip.Equal(l) {
			ok = true
			return
		}
	}

	return
}

func extractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	out := []dns.RR{}
	tMap := make(map[uint16]struct{}, len(t))
	for _, t := range t {
		tMap[t] = struct{}{}
	}
	for _, r := range in {
		if _, ok := tMap[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

func verifyDS(keyMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) (bool, error) {
	unsupportedDigest := false
	for i, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
		}

		if parentDS.DigestType == dns.GOST94 {
			unsupportedDigest = true
		}

		ksk, present := keyMap[parentDS.KeyTag]
		if !present {
			continue
		}
		//TODO: miek dns lib doesn't support GOST 34.11 currently
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errMismatchingDS
		}
		return unsupportedDigest, nil
	}

	return unsupportedDigest, errMissingKSK
}

func isDO(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}

	return false
}

func verifyRRSIG(keys map[uint16]*dns.DNSKEY, msg *dns.Msg) (bool, error) {
	rr := msg.Answer
	if len(rr) == 0 {
		rr = msg.Ns
	}

	sigs := extractRRSet(rr, "", dns.TypeRRSIG)
	if len(sigs) == 0 {
		return false, errNoSignatures
	}

	types := make(map[uint16]int)
	typesErrors := make(map[uint16][]struct{})

	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		types[sig.TypeCovered]++
	}

main:
	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		for _, k := range keys {
			if !strings.HasSuffix(sig.Header().Name, k.Header().Name) {
				continue main
			}
			if sig.SignerName != k.Header().Name {
				continue main
			}
		}

		rest := extractRRSet(rr, strings.ToLower(sig.Header().Name), sig.TypeCovered)
		if len(rest) == 0 {
			return false, errMissingSigned
		}
		k, ok := keys[sig.KeyTag]
		if !ok {
			if len(typesErrors[sig.TypeCovered]) < types[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
				continue
			}
			return false, errMissingDNSKEY
		}
		switch k.Algorithm {
		case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.RSAMD5:
			if !checkExponent(k.PublicKey) {
				return false, nil
			}
		}
		err := sig.Verify(k, rest)
		if err != nil {
			if len(typesErrors[sig.TypeCovered]) < types[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
				typesErrors[sig.TypeCovered] = append(typesErrors[sig.TypeCovered], struct{}{})
				continue
			}
			return false, err
		}
		if !sig.ValidityPeriod(time.Time{}) {
			if types[sig.TypeCovered] > 1 {
				continue
			}
			return false, errInvalidSignaturePeriod
		}
	}

	return true, nil
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func verifyNSEC(q dns.Question, nsecSet []dns.RR) (typeMatch bool) {
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		for _, t := range nsec.TypeBitMap {
			if t == q.Qtype {
				typeMatch = true
				break
			}
		}
	}

	return
}

func checkExponent(key string) bool {
	keybuf, err := fromBase64([]byte(key))
	if err != nil {
		return true
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return true
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return false
	}

	return true
}

/*
sorts the nameservers descendingly according to how many labels they have in common with the Qname
example: given two Ns  ns1.dummy.example.org.  ns.example.org. and a qname test.dummy.example.org.

	the snd Ns will preceede the fst as it has 2 label in common with the qname, whereas the fst has 3
*/
func sortnss(nss nameservers, qname string) []string {
	var list []string // contains the keys of nameservers map
	for name := range nss {
		list = append(list, name)
	}

	sort.Strings(list)
	// nameservers sorted lexicogryphically, so that shorter ones preceede longer ones
	sort.Slice(list, func(i, j int) bool {
		return dns.CompareDomainName(qname, list[i]) < dns.CompareDomainName(qname, list[j])
	})

	return list
}

/*
Alias for a name and all its subnames, unlike CNAME, which is an alias for only the exact name.
Like a CNAME record, the DNS lookup will continue by retrying the lookup with the new name.

A DNAME record or Delegation Name record is defined by RFC 6672 (original RFC 2672 is now obsolete). A DNAME record creates an alias for an entire subtree of the domain name tree. In contrast, the CNAME record creates an alias for a single name and not its subdomains. Like the CNAME record, the DNS lookup will continue by retrying the lookup with the new name. The name server synthesizes a CNAME record to actually apply the DNAME record to the requested name—CNAMEs for every node on a subtree have the same effect as a DNAME for the entire subtree.

For example, if there is a DNS zone as follows:

foo.example.com.        DNAME  bar.example.com.
bar.example.com.        A      192.0.2.23
xyzzy.bar.example.com.  A      192.0.2.24
*.bar.example.com.      A      192.0.2.25
An A record lookup for foo.example.com will return no data because a DNAME is not a CNAME and there is no A record directly at foo.

However, a lookup for xyzzy.foo.example.com will be DNAME mapped and return the A record for xyzzy.bar.example.com, which is 192.0.2.24;
if the DNAME record had been a CNAME record, this request would have returned name not found.

Lastly, a request for foobar.foo.example.com would be DNAME mapped and return 192.0.2.25.

\brief gets the target domain where the question in msg is eventually delegated to,

	if its Answer section contains a DNAME RR that is relevant for the question
*/
func getDnameTarget(msg *dns.Msg) string {
	var target string

	q := msg.Question[0]

	for _, r := range msg.Answer {
		if dname, ok := r.(*dns.DNAME); ok {
			delegateFrom := dname.Header().Name // domain name that is delegated
			// check if the query is affected by the delegation (query )
			if n := dns.CompareDomainName(delegateFrom, q.Name); n > 0 {
				labels := dns.CountLabel(q.Name)

				if n == labels {
					// question matches the delegateFrom-domain exactly (it holds delegateFrom==q.Name)
					target = dname.Target
				} else {
					// question is only partially affected (the last 'n' labels are delegated, and replaced by target)
					prev, _ := dns.PrevLabel(q.Name, n)
					target = q.Name[:prev] + dname.Target
				}
			}

			return target
		}
	}

	return target
}

/*
q must be an element of msg.Question
*/
func getDnameTargetForQuestion(msg *dns.Msg, q dns.Question) string {
	var target string

	for _, r := range msg.Answer {
		if dname, ok := r.(*dns.DNAME); ok {
			delegateFrom := dname.Header().Name // domain name that is delegated
			// check if the query is affected by the delegation (query )
			if n := dns.CompareDomainName(delegateFrom, q.Name); n > 0 {
				labels := dns.CountLabel(q.Name)

				if n == labels {
					// question matches the delegateFrom-domain exactly (it holds delegateFrom==q.Name)
					target = dname.Target
				} else {
					// question is only partially affected (the last 'n' labels are delegated, and replaced by target)
					prev, _ := dns.PrevLabel(q.Name, n)
					target = q.Name[:prev] + dname.Target
				}
			}

			return target
		}
	}

	return target
}

var reqPool sync.Pool

// AcquireMsg returns an empty msg from pool
func AcquireMsg() *dns.Msg {
	v := reqPool.Get()
	if v == nil {
		return &dns.Msg{}
	}

	return v.(*dns.Msg)
}

// ReleaseMsg returns req to pool
func ReleaseMsg(req *dns.Msg) {
	req.Id = 0
	req.Response = false
	req.Opcode = 0
	req.Authoritative = false
	req.Truncated = false
	req.RecursionDesired = false
	req.RecursionAvailable = false
	req.Zero = false
	req.AuthenticatedData = false
	req.CheckingDisabled = false
	req.Rcode = 0
	req.Compress = false
	req.Question = nil
	req.Answer = nil
	req.Ns = nil
	req.Extra = nil

	reqPool.Put(req)
}

var connPool sync.Pool

// AcquireConn returns an empty conn from pool
func AcquireConn() *Conn {
	v := connPool.Get()
	if v == nil {
		return &Conn{}
	}
	return v.(*Conn)
}

// ReleaseConn returns req to pool
func ReleaseConn(co *Conn) {
	if co.Conn != nil {
		_ = co.Conn.Close()
	}

	co.UDPSize = 0
	co.Conn = nil

	connPool.Put(co)
}
