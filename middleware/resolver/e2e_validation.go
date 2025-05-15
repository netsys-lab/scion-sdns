package resolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var errExpired error = errors.New("DNSKEY expired")
var errNoEntries error = errors.New("Empty signature input, nothing to check")

const (
	DNSrhineCertPrefix = "_rhinecert."
	DNSdspprefix       = "_dsp."

	txtrhinecertprefix = "rhineCert "
	txtsigvalueprefix  = "rhineSig " // TODO unused !!
	defaultUDPBufSize  = 2048
)

type ROA struct {
	Domain string
	rcert  *dns.TXT
	dsp    *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG
}

func Size(m *dns.Msg) {
	o := m.IsEdns0()
	if o != nil {
		o.SetUDPSize(defaultUDPBufSize)
		return
	}

	o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(defaultUDPBufSize)
	m.Extra = append(m.Extra, o)
}

// this should move into the miekg/dns package
func x509PubAlgoCodeToDNS(cert *x509.Certificate) (uint8, error) {

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:

		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA:
			return dns.RSASHA1, nil
		case x509.SHA256WithRSA:
			return dns.RSASHA256, nil
		//case x509.SHA384WithRSA:
		case x509.SHA512WithRSA:
			return dns.RSASHA512, nil
		case x509.MD5WithRSA:
			return dns.RSAMD5, nil
		}

		//dns.RSASHA1NSEC3SHA1

	case x509.ECDSA:

		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			return dns.ECDSAP256SHA256, nil
		case x509.ECDSAWithSHA384:
			return dns.ECDSAP384SHA384, nil
		}

	case x509.Ed25519:
		// assert SignatureAlgorithm is x509.PureEd25519 ?!
		return dns.ED25519, nil
	}

	return 0, fmt.Errorf("unsupported certificate PublicKeyAlgorithm: %s SignatureAlgorithm: %s",
		cert.PublicKeyAlgorithm.String(),
		cert.SignatureAlgorithm.String())
}

/*loads RHINE CA certificate in PEM format from file*/
func LoadRHINECert(rhinecertificate string) ([]byte, error) {

	var cert []byte
	if rhinecertificate != "" {
		if bytes, err := os.ReadFile(rhinecertificate); err != nil {

			fmt.Fprintf(os.Stderr, "Failure to open %s: %s\n", rhinecertificate, err.Error())
			return nil, err
		} else {
			cert = bytes
			return cert, nil
		}
	}
	return nil, errors.New("path to rhineCertificate was invalid")

}

/*
@param cert the RHINE CA Certificate loaded from file.

	It serves as trust anchor to verify the roa received with the DNS response.
	If the roa isn't authentic we can't use it to validate any RRSIGs in the response.
*/
func VerifyRhineROA(roa *ROA, cert []byte) bool {
	rcert, publicKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, cert)
	if err != nil {
		fmt.Printf("[RHINE] RCert parse faild, error: %s\n", err.Error())
		return false
	}
	fmt.Printf("[RHINE] RCert successfully parsed and authenticated\n")

	algocode, err := x509PubAlgoCodeToDNS(rcert)
	if err != nil {
		fmt.Printf("[RHINE] %s\n", err.Error())
		return false
	}

	key := &dns.DNSKEY{Flags: 257, //256=Zone und 257=key
		Protocol:  3,
		Algorithm: algocode}

	key.Hdr = dns.RR_Header{Name: roa.keySig.SignerName, // has to be DNSName or SubjectName of the RHINE cert ?!
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    roa.keySig.OrigTtl,
	}

	key.PublicKey = base64.StdEncoding.EncodeToString(publicKey[1:])
	fmt.Printf("[RHINE] key tag of RHINE public key: %d and RRSIG(DNSKEY): %d\n", key.KeyTag(), roa.keySig.KeyTag)

	//originalKey := ParsePKIXPublicKey( publicKey )  i.e. for ECDSA publickey was marshalled into PKIX, ASN.1 DER form before base64 encoding

	/*
		 what's asserted here is, that the private key corresponding to the rhine cert's public key
		 has been used to create the ROA's RRSIG of the DNSKEY

			Is roa.keySig RRSIG really the signature of 'roa.dnskey' created with the private key corresponding to 'key' ??
	*/

	if err := roa.keySig.Verify(key, []dns.RR{roa.dnskey}); err != nil {

		fmt.Printf("[RHINE] RhineSig verification failed, %s \n", err)
		return false
	} else {
		fmt.Printf("[RHINE] RhineSig successfully verified\n")
		return true
	}

}

/*
* returns RHINE certificate and public key parsed from the TXT RR
@param CaCert the RHINE CA Certificate
*/
func ParseVerifyRhineCertTxtEntry(txt *dns.TXT, CaCert []byte) (*x509.Certificate, []byte, error) {

	entries := txt.Txt
	entry := strings.Join(entries, "")
	_certstringchunks := strings.SplitAfter(entry, txtrhinecertprefix)[1:] // remove the 'rhineCert' token
	_cert := strings.Join(_certstringchunks, "")
	certstringchunks := strings.SplitAfter(_cert, " ")[1:] //remove the public key algo
	encodedcert := strings.Join(certstringchunks, "")
	encodedcert = strings.ReplaceAll(encodedcert, " ", "")

	certdecoded, err := base64.StdEncoding.DecodeString(encodedcert)
	if err != nil {
		fmt.Println("Decoding Rhine Cert failed! ", err)
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		fmt.Println("Parsing Rhine Cert failed! ", err)
		return nil, nil, err
	}

	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]
	// Now vertify the RHINE certificate retrieved from the TXT RR
	// with the RHINE CA cert
	var CaCertPool *x509.CertPool
	CaCertPool, _ = x509.SystemCertPool()

	CaCertPool.AppendCertsFromPEM(CaCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   CaCertPool,
	}); err != nil {
		fmt.Println("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	var pubkeybytes []byte
	// Convert the public key to raw bytes

	algocode, err := x509PubAlgoCodeToDNS(cert)
	if err != nil {
		return nil, nil, err
	}

	switch algocode {
	case dns.ECDSAP256SHA256:
		// pubkeybytes = elliptic.Marshal(elliptic.P256(), cert.PublicKey.(*ecdsa.PublicKey).X, cert.PublicKey.(*ecdsa.PublicKey).Y)
		pcdh, err := cert.PublicKey.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, nil, err
		}
		pubkeybytes = pcdh.Bytes()
	case dns.ECDSAP384SHA384:
		pubkeybytes = elliptic.Marshal(elliptic.P384(), cert.PublicKey.(*ecdsa.PublicKey).X, cert.PublicKey.(*ecdsa.PublicKey).Y)
	case dns.ED25519:
		pubkeybytes = cert.PublicKey.(ed25519.PublicKey) //.([]byte)
	default:
		// FIXME: this is probably wrong ^^ with ECDSAP384 it produced length 120 bytes, instead of the expected 97
		_rawkeybytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		pubkeybytes = _rawkeybytes
	}

	return cert, pubkeybytes, nil
}

func hash(qname string) uint64 {
	h := fnv.New64()
	h.Write([]byte(qname))
	return h.Sum64()
}

/*
 */
func ExtractROAFromMsg(msg *dns.Msg) (roa *ROA, ok bool) {
	var (
		rcert  *dns.TXT    // _rhinecert.<domain.name> TXT ...
		dnskey *dns.DNSKEY // the public key of <domain.name>
		keySig *dns.RRSIG  // the signature of 'dnskey' RR generated with the corresponding private key to 'dnskey'
		dsp    *dns.TXT    // _dsp.<parent.zone> TXT "<subzone>"
	)

	for _, r := range append(msg.Answer, msg.Extra...) {
		switch r.Header().Rrtype {
		case dns.TypeDNSKEY:
			dnskey = r.(*dns.DNSKEY)
		case dns.TypeTXT:
			txt := r.(*dns.TXT)
			if IsRCert(txt) {
				rcert = txt
			} else if IsDSP(txt) {
				dsp = txt
			}
		case dns.TypeRRSIG:
			rrsig := r.(*dns.RRSIG)
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				keySig = rrsig
			}
		}
	}
	if rcert == nil || dnskey == nil || keySig == nil {
		fmt.Printf("[RHINE] ;? Correct ROA not found in Msg:\n%+v", msg)
		if rcert == nil {
			fmt.Printf("[RHINE] ;? RCert is null\n")
		}
		if dnskey == nil {
			fmt.Printf("[RHINE] ;? DNSKEY is null\n")
		}
		if keySig == nil {
			fmt.Printf("[RHINE] ;? keySig is null\n")
		}
		return nil, false
	}
	domain := strings.SplitAfter(rcert.Header().Name, DNSrhineCertPrefix)[1]
	fmt.Printf("[RHINE] ROA for %s successfully extracted from response\n", domain)
	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dsp: dsp, Domain: domain}, true
}

func addROAToMsg(roa *ROA, msg *dns.Msg) {
	msg.Extra = append(msg.Extra, roa.dnskey)
	msg.Extra = append(msg.Extra, roa.rcert)
	msg.Extra = append(msg.Extra, roa.keySig)
	if roa.dsp != nil {
		msg.Extra = append(msg.Extra, roa.dsp)
	}
}

/*
 */
func RhineRRSigCheckROA(in *dns.Msg, roa *ROA) {
	if roa != nil {
		key := roa.dnskey
		RhineRRSigCheck(in, key)
	}
}

func RhineRRSigCheck(in *dns.Msg, key *dns.DNSKEY) (error, bool) {
	if key == nil {
		fmt.Printf("[RHINE] DNSKEY not found for RRSIG checking\n")
		return errors.New("[RHINE] DNSKEY not found for RRSIG checking"), false
	}
	fmt.Printf("[RHINE] Start checking RRSIG in Answer section\n")
	// FIXME: here NoEntries IS an error !! if there's a ROA then there has to be a (valid) RRSIG as well !
	if err, valid := rhineSectionCheck(in.Answer, key); (err != nil) || !valid {
		return err, valid
	}
	// TODO for which type of query do we expect NS records in the response ?! is this an error or not
	fmt.Printf("[RHINE] Start checking RRSIG in Ns section\n")
	if err, valid := rhineSectionCheck(in.Ns, key); (err != errNoEntries && err != nil) || !valid {
		return err, valid
	}
	return nil, true
}

// shortSig shortens RRSIG to "miek.nl RRSIG(NS)"
func ShortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

// Return the RRset belonging to the signature with name and type t
func GetRRset(l []dns.RR, name string, t uint16) []dns.RR {
	var l1 []dns.RR
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

/*
verify that DNSKEY 'key' (public key) in fact created the RRSIG signature contained in 'set'
*/
func rhineSectionCheck(set []dns.RR, key *dns.DNSKEY) (error, bool) {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
				return errExpired, false
			}
			rrset := GetRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf("[RHINE] ;- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					ShortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
				return err, false
			} else {
				fmt.Printf("[RHINE] ;+ Secure signature, %s validates (DNSKEY %s/%d) %s\n",
					ShortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
				/* ;+ Secure signature, example.com. RRSIG(NS) validates (DNSKEY example.com./35343)
				which says the NS has a valid RRSIG and it validated with the DNSKEY of example.com. which has key id 35343
				*/
				return nil, true
			}
		}
	}
	return errNoEntries, false
}

func IsRCert(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSrhineCertPrefix)
}

func IsDSP(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdspprefix)
}

// TODO  this is never used aywhere
func IsRhineSig(txt *dns.TXT) bool {
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	return strings.HasPrefix(entry, txtsigvalueprefix)
}
