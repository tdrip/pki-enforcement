package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"regexp"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
)

type zoneConfigEntry struct {
	ExtKeyUsage            []x509.ExtKeyUsage `json:"ext_key_usage"`
	AutoRefreshInterval    int64              `json:"auto_refresh_interval"`
	LastPolicyUpdateTime   int64              `json:"last_policy_update_time"`
	VenafiImportTimeout    int                `json:"import_timeout"`
	VenafiImportWorkers    int                `json:"import_workers"`
	VenafiSecret           string             `json:"venafi_secret"`
	Zone                   string             `json:"zone"`
	ImportOnlyNonCompliant bool               `json:"import_only_non_compliant"`
}

func checkAgainstVenafiZone(req *logical.Request, role *roleEntry, isCA bool, csr *x509.CertificateRequest, cn string, ipAddresses, email, sans []string) error {

	if len(role.Zone) == 0 {
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

	if csr != nil {
		log.Printf("%s Checking CSR against zone %v", logPrefixVenafiPolicyEnforcement, role)
		if isCA {
			if len(csr.EmailAddresses) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if csr.DNSNames[0] != csr.Subject.CommonName {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
				}
			}
		} else {
			if !checkStringByRegexp(csr.Subject.CommonName, role.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, role.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(csr.EmailAddresses, role.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, role.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(csr.DNSNames, role.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, role.DnsSanRegExs)
			}
			ips := make([]string, len(csr.IPAddresses))
			for i, ip := range csr.IPAddresses {
				ips[i] = ip.String()
			}
			if !checkStringArrByRegexp(ips, role.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, role.IpSanRegExs)
			}
			uris := make([]string, len(csr.URIs))
			for i, uri := range csr.URIs {
				uris[i] = uri.String()
			}
			if !checkStringArrByRegexp(uris, role.UriSanRegExs, true) {
				return fmt.Errorf("URI SANs %v do not match regexps: %v", uris, role.UriSanRegExs)
			}
		}
		if !checkStringArrByRegexp(csr.Subject.Organization, role.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, role.SubjectORegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, role.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, role.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Country, role.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", csr.Subject.Country, role.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Locality, role.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", csr.Subject.Locality, role.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Province, role.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", csr.Subject.Province, role.SubjectSTRegexes)
		}
		keyValid := true
		if csr.PublicKeyAlgorithm == x509.RSA {
			pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
			if ok {
				keyValid = checkKey("rsa", pubKey.Size()*8, "", role.AllowedKeyConfigurations)
			} else {
				log.Printf("%s invalid key in CSR", logPrefixVenafiPolicyEnforcement)
			}
		} else if csr.PublicKeyAlgorithm == x509.ECDSA {
			pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if ok {
				keyValid = checkKey("ecdsa", 0, pubKey.Curve.Params().Name, role.AllowedKeyConfigurations)
			}
		}
		if !keyValid {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}
	} else {
		log.Printf("%s Checking creation bundle against policy %v", logPrefixVenafiPolicyEnforcement, role)

		if isCA {
			if len(email) != 0 || len(sans) != 0 || len(ipAddresses) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if sans[0] != cn {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v", email, sans, ipAddresses)
				}
			}
		} else {
			if !checkStringByRegexp(cn, role.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, role.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(email, role.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, role.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(sans, role.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", sans, role.DnsSanRegExs)
			}
			if !checkStringArrByRegexp(ipAddresses, role.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, role.IpSanRegExs)
			}
		}

		if !checkStringArrByRegexp(role.Organization, role.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, role.SubjectORegexes)
		}

		if !checkStringArrByRegexp(role.OU, role.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", role.OU, role.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(role.Country, role.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", role.Country, role.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(role.Locality, role.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", role.Locality, role.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(role.Province, role.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", role.Province, role.SubjectSTRegexes)
		}
		if !checkKey(role.KeyType, role.KeyBits, ecdsaCurvesSizesToName(role.KeyBits), role.AllowedKeyConfigurations) {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}

	}

	//TODO: check against upn_san_regexes
	extKeyUsage, err := parseExtKeyUsageParameter(role.ExtKeyUsage)
	if err != nil {
		return err
	}
	if !isCA {
		if !compareEkuList(extKeyUsage, role.VExtKeyUsage) {
			return fmt.Errorf("different EKU in Venafi zone config and role")
		}
	}

	return nil
}

func checkCSRAgainstZoneEntry(isCA bool, csr *x509.CertificateRequest, zone roleEntry) error {
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

func (b *backend) getZoneFromVenafi(ctx context.Context, storage *logical.Storage, zone string, role string) (policy *endpoint.Policy, err error) {
	log.Printf("%s Creating Venafi client", logPrefixVenafiPolicyEnforcement)

	cl, err := b.RoleBasedClientVenafi(ctx, storage, zone, role)
	if err != nil {
		return
	}
	log.Printf("%s Getting policy from Venafi endpoint", logPrefixVenafiPolicyEnforcement)

	policy, err = cl.ReadPolicyConfiguration()
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {

			cfg, err := b.getRoleBasedConfig(ctx, storage, zone, role)

			if err != nil {
				return nil, err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = synchronizedUpdateAccessToken(cfg, b, ctx, storage, zone)

				if err != nil {
					return nil, err
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, err := b.RoleBasedClientVenafi(ctx, storage, zone, role)
				if err != nil {
					return nil, err
				}

				b.Logger().Debug("Making certificate request again")

				policy, err = cl.ReadPolicyConfiguration()
				if err != nil {
					return nil, err
				} else {
					return policy, nil
				}
			} else {
				err = fmt.Errorf("tried to get new access token but refresh token is empty")
				return nil, err
			}

		} else {
			return nil, err
		}
	}
	if policy == nil {
		err = fmt.Errorf("expected policy but got nil from Venafi endpoint %v", policy)
		return
	}

	return
}

func (b *backend) getRoleEntryFromVenafi(ctx context.Context, storage *logical.Storage, path string, role *roleEntry) (zoneentry *roleEntry, err error) {
	// grab the zone from Venafi
	zone, err := b.getZoneFromVenafi(ctx, storage, path, role.Name)
	if err != nil {
		return nil, err
	}

	// Venafi have this concept of zone/policy which is interchangeable
	// Vault has policy
	// we shall stick to zone so that it is clear
	// this is a venafi zone (path in a venafi platform)

	role.SubjectCNRegexes = zone.SubjectCNRegexes
	role.SubjectORegexes = zone.SubjectORegexes
	role.SubjectOURegexes = zone.SubjectOURegexes
	role.SubjectSTRegexes = zone.SubjectSTRegexes
	role.SubjectLRegexes = zone.SubjectLRegexes
	role.SubjectCRegexes = zone.SubjectCRegexes
	role.AllowedKeyConfigurations = zone.AllowedKeyConfigurations
	role.DnsSanRegExs = zone.DnsSanRegExs
	role.IpSanRegExs = zone.IpSanRegExs
	role.EmailSanRegExs = zone.EmailSanRegExs
	role.UriSanRegExs = zone.UriSanRegExs
	role.UpnSanRegExs = zone.UpnSanRegExs
	role.AllowWildcards = zone.AllowWildcards
	role.AllowKeyReuse = zone.AllowKeyReuse

	return role, nil
}

/*
func (b *backend) getZoneEntryFromVenafi(ctx context.Context, storage *logical.Storage, path string, role string) (zoneentry *zoneEntry, err error) {
	// grab the zone from Venafi
	zone, err := b.getZoneFromVenafi(ctx, storage, path, role)
	if err != nil {
		return nil, err
	}

	// Venafi have this concept of zone/policy which is interchangeable
	// Vault has policy
	// we shall stick to zone so that it is clear
	// this is a venafi zone (path in a venafi platform)
	zoneentry = &zoneEntry{
		SubjectCNRegexes:         zone.SubjectCNRegexes,
		SubjectORegexes:          zone.SubjectORegexes,
		SubjectOURegexes:         zone.SubjectOURegexes,
		SubjectSTRegexes:         zone.SubjectSTRegexes,
		SubjectLRegexes:          zone.SubjectLRegexes,
		SubjectCRegexes:          zone.SubjectCRegexes,
		AllowedKeyConfigurations: zone.AllowedKeyConfigurations,
		DnsSanRegExs:             zone.DnsSanRegExs,
		IpSanRegExs:              zone.IpSanRegExs,
		EmailSanRegExs:           zone.EmailSanRegExs,
		UriSanRegExs:             zone.UriSanRegExs,
		UpnSanRegExs:             zone.UpnSanRegExs,
		AllowWildcards:           zone.AllowWildcards,
		AllowKeyReuse:            zone.AllowKeyReuse,
	}
	return zoneentry, nil
}


func formZoneRespData(zone zoneEntry) (respData map[string]interface{}) {
	type printKeyConfig struct {
		KeyType   string
		KeySizes  []int    `json:",omitempty"`
		KeyCurves []string `json:",omitempty"`
	}
	keyConfigs := make([]string, len(zone.AllowedKeyConfigurations))
	for i, akc := range zone.AllowedKeyConfigurations {
		kc := printKeyConfig{akc.KeyType.String(), akc.KeySizes, nil}
		if akc.KeyType == certificate.KeyTypeECDSA {
			kc.KeyCurves = make([]string, len(akc.KeyCurves))
			for i, c := range akc.KeyCurves {
				kc.KeyCurves[i] = c.String()
			}
		}
		kb, _ := json.Marshal(kc)
		keyConfigs[i] = string(kb)
	}
	return map[string]interface{}{
		"subject_cn_regexes":         zone.SubjectCNRegexes,
		"subject_o_regexes":          zone.SubjectORegexes,
		"subject_ou_regexes":         zone.SubjectOURegexes,
		"subject_st_regexes":         zone.SubjectSTRegexes,
		"subject_l_regexes":          zone.SubjectLRegexes,
		"subject_c_regexes":          zone.SubjectCRegexes,
		"allowed_key_configurations": keyConfigs,
		"dns_san_regexes":            zone.DnsSanRegExs,
		"ip_san_regexes":             zone.IpSanRegExs,
		"email_san_regexes":          zone.EmailSanRegExs,
		"uri_san_regexes":            zone.UriSanRegExs,
		"upn_san_regexes":            zone.UpnSanRegExs,
		"allow_wildcards":            zone.AllowWildcards,
		"allow_key_reuse":            zone.AllowKeyReuse,
	}
}
*/
