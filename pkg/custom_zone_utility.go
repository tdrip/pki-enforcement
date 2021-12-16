package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
)

func checkAgainstVenafiZone(
	req *logical.Request,
	role *roleEntry,
	isCA bool,
	csr *x509.CertificateRequest,
	cn string,
	ipAddresses, email, sans []string) error {
	if role.VenafiZone == nil {
		if venafiPolicyDenyAll {
			//TODO: Can not understand why I added this if here. Probably should be removed
			//if strings.Contains(req.Path, "root/generate") {
			//	log.Println("zone data is nil. You need configure Venafi zone to proceed")
			//}
			return fmt.Errorf("zone data is nil. You need configure Venafi zone to proceed")
		} else {
			return nil
		}
	}

	policy := role.VenafiZone

	if csr != nil {
		log.Printf("%s Checking CSR against zone %v", logPrefixVenafiPolicyEnforcement, role.VenafiZone)
		if isCA {
			if len(csr.EmailAddresses) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if csr.DNSNames[0] != csr.Subject.CommonName {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
				}
			}
		} else {
			if !checkStringByRegexp(csr.Subject.CommonName, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(csr.EmailAddresses, policy.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(csr.DNSNames, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, policy.DnsSanRegExs)
			}
			ips := make([]string, len(csr.IPAddresses))
			for i, ip := range csr.IPAddresses {
				ips[i] = ip.String()
			}
			if !checkStringArrByRegexp(ips, policy.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
			uris := make([]string, len(csr.URIs))
			for i, uri := range csr.URIs {
				uris[i] = uri.String()
			}
			if !checkStringArrByRegexp(uris, policy.UriSanRegExs, true) {
				return fmt.Errorf("URI SANs %v do not match regexps: %v", uris, policy.UriSanRegExs)
			}
		}
		if !checkStringArrByRegexp(csr.Subject.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, policy.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", csr.Subject.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", csr.Subject.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", csr.Subject.Province, policy.SubjectSTRegexes)
		}
		keyValid := true
		if csr.PublicKeyAlgorithm == x509.RSA {
			pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
			if ok {
				keyValid = checkKey("rsa", pubKey.Size()*8, "", policy.AllowedKeyConfigurations)
			} else {
				log.Printf("%s invalid key in CSR", logPrefixVenafiPolicyEnforcement)
			}
		} else if csr.PublicKeyAlgorithm == x509.ECDSA {
			pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if ok {
				keyValid = checkKey("ecdsa", 0, pubKey.Curve.Params().Name, policy.AllowedKeyConfigurations)
			}
		}
		if !keyValid {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}
	} else {
		log.Printf("%s Checking creation bundle against policy %v", logPrefixVenafiPolicyEnforcement, policy)

		if isCA {
			if len(email) != 0 || len(sans) != 0 || len(ipAddresses) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if sans[0] != cn {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v", email, sans, ipAddresses)
				}
			}
		} else {
			if !checkStringByRegexp(cn, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(email, policy.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(sans, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", sans, policy.DnsSanRegExs)
			}
			if !checkStringArrByRegexp(ipAddresses, policy.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
		}

		if !checkStringArrByRegexp(role.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(role.OU, policy.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", role.OU, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(role.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", role.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(role.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(role.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", role.Province, policy.SubjectSTRegexes)
		}
		if !checkKey(role.KeyType, role.KeyBits, ecdsaCurvesSizesToName(role.KeyBits), policy.AllowedKeyConfigurations) {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}

	}

	//TODO: check against upn_san_regexes
	extKeyUsage, err := parseExtKeyUsageParameter(role.ExtKeyUsage)
	if err != nil {
		return err
	}
	if !isCA {
		if !compareEkuList(extKeyUsage, policy.ExtKeyUsage) {
			return fmt.Errorf("different EKU in Venafi zone config and role")
		}
	}

	return nil
}

func checkCSRAgainstZone(isCA bool, csr *x509.CertificateRequest, zone venafiZoneEntry) error {
	if isCA {
		if len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || (len(csr.DNSNames) != 0 &&
			csr.DNSNames[0] != csr.Subject.CommonName) { //workaround for setting SAN if CA have normal domain in CN
			return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
		}
	} else {
		if !checkStringByRegexp(csr.Subject.CommonName, zone.SubjectCNRegexes) {
			return fmt.Errorf("common name %s doesn't match regexps: %v", csr.Subject.CommonName, zone.SubjectCNRegexes)
		}
		if !checkStringArrByRegexp(csr.EmailAddresses, zone.EmailSanRegExs, true) {
			return fmt.Errorf("email SANs %v do not match regexps: %v", csr.EmailAddresses, zone.EmailSanRegExs)
		}
		if !checkStringArrByRegexp(csr.DNSNames, zone.DnsSanRegExs, true) {
			return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, zone.DnsSanRegExs)
		}
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		if !checkStringArrByRegexp(ips, zone.IpSanRegExs, true) {
			return fmt.Errorf("IP SANs %v do not match regexps: %v", ips, zone.IpSanRegExs)
		}
		uris := make([]string, len(csr.URIs))
		for i, uri := range csr.URIs {
			uris[i] = uri.String()
		}
		if !checkStringArrByRegexp(uris, zone.UriSanRegExs, true) {
			return fmt.Errorf("URI SANs %v do not match regexps: %v", uris, zone.UriSanRegExs)
		}
	}
	if !checkStringArrByRegexp(csr.Subject.Organization, zone.SubjectORegexes, false) {
		return fmt.Errorf("organization %v doesn't match regexps: %v", csr.Subject.Organization, zone.SubjectORegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, zone.SubjectOURegexes, false) {
		return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, zone.SubjectOURegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Country, zone.SubjectCRegexes, false) {
		return fmt.Errorf("country %v doesn't match regexps: %v", csr.Subject.Country, zone.SubjectCRegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Locality, zone.SubjectLRegexes, false) {
		return fmt.Errorf("city (locality) %v doesn't match regexps: %v", csr.Subject.Locality, zone.SubjectLRegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Province, zone.SubjectSTRegexes, false) {
		return fmt.Errorf("state (province) %v doesn't match regexps: %v", csr.Subject.Province, zone.SubjectSTRegexes)
	}
	keyValid := true
	if csr.PublicKeyAlgorithm == x509.RSA {
		pubkey, ok := csr.PublicKey.(*rsa.PublicKey)
		if ok {
			keyValid = checkKey("rsa", pubkey.Size()*8, "", zone.AllowedKeyConfigurations)
		} else {
			log.Printf("%s invalid key in CSR", logPrefixVenafiPolicyEnforcement)
		}
	} else if csr.PublicKeyAlgorithm == x509.ECDSA {
		pubkey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if ok {
			keyValid = checkKey("ecdsa", 0, pubkey.Curve.Params().Name, zone.AllowedKeyConfigurations)
		}
	}
	if !keyValid {
		return fmt.Errorf("key type is not allowed by Venafi")
	}
	return nil
}

type venafiZoneEntry struct {
	ExtKeyUsage              []x509.ExtKeyUsage                 `json:"ext_key_usage"`
	SubjectCNRegexes         []string                           `json:"subject_cn_regexes"`
	SubjectORegexes          []string                           `json:"subject_o_regexes"`
	SubjectOURegexes         []string                           `json:"subject_ou_regexes"`
	SubjectSTRegexes         []string                           `json:"subject_st_regexes"`
	SubjectLRegexes          []string                           `json:"subject_l_regexes"`
	SubjectCRegexes          []string                           `json:"subject_c_regexes"`
	AllowedKeyConfigurations []endpoint.AllowedKeyConfiguration `json:"allowed_key_configurations"`
	DnsSanRegExs             []string                           `json:"dns_san_regexes"`
	IpSanRegExs              []string                           `json:"ip_san_regexes"`
	EmailSanRegExs           []string                           `json:"email_san_regexes"`
	UriSanRegExs             []string                           `json:"uri_san_regexes"`
	UpnSanRegExs             []string                           `json:"upn_san_regexes"`
	AllowWildcards           bool                               `json:"allow_wildcards"`
	AllowKeyReuse            bool                               `json:"allow_key_reuse"`
	ImportZone               string                             `json:"import_zone"`
	Zone                     string                             `json:"zone"`
	ConfigPath               string                             `json:"config_path"`
}

func NewVenafiZoneEntry() *venafiZoneEntry {
	ve := venafiZoneEntry{}

	return &ve
}
