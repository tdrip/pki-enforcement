package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const logPrefixEnforcement = "ENFORCEMENT: "

var venafiPolicyDenyAll = true

type roleEntry struct {
	LeaseMax                      string        `json:"lease_max"`
	Lease                         string        `json:"lease"`
	DeprecatedMaxTTL              string        `json:"max_ttl" mapstructure:"max_ttl"`
	DeprecatedTTL                 string        `json:"ttl" mapstructure:"ttl"`
	TTL                           time.Duration `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL                        time.Duration `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
	AllowLocalhost                bool          `json:"allow_localhost" mapstructure:"allow_localhost"`
	AllowedBaseDomain             string        `json:"allowed_base_domain" mapstructure:"allowed_base_domain"`
	AllowedDomainsOld             string        `json:"allowed_domains,omitempty"`
	AllowedDomains                []string      `json:"allowed_domains_list" mapstructure:"allowed_domains"`
	AllowedDomainsTemplate        bool          `json:"allowed_domains_template"`
	AllowBaseDomain               bool          `json:"allow_base_domain"`
	AllowBareDomains              bool          `json:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowTokenDisplayName         bool          `json:"allow_token_displayname" mapstructure:"allow_token_displayname"`
	AllowSubdomains               bool          `json:"allow_subdomains" mapstructure:"allow_subdomains"`
	AllowGlobDomains              bool          `json:"allow_glob_domains" mapstructure:"allow_glob_domains"`
	AllowAnyName                  bool          `json:"allow_any_name" mapstructure:"allow_any_name"`
	EnforceHostnames              bool          `json:"enforce_hostnames" mapstructure:"enforce_hostnames"`
	AllowIPSANs                   bool          `json:"allow_ip_sans" mapstructure:"allow_ip_sans"`
	ServerFlag                    bool          `json:"server_flag" mapstructure:"server_flag"`
	ClientFlag                    bool          `json:"client_flag" mapstructure:"client_flag"`
	CodeSigningFlag               bool          `json:"code_signing_flag" mapstructure:"code_signing_flag"`
	EmailProtectionFlag           bool          `json:"email_protection_flag" mapstructure:"email_protection_flag"`
	UseCSRCommonName              bool          `json:"use_csr_common_name" mapstructure:"use_csr_common_name"`
	UseCSRSANs                    bool          `json:"use_csr_sans" mapstructure:"use_csr_sans"`
	KeyType                       string        `json:"key_type" mapstructure:"key_type"`
	KeyBits                       int           `json:"key_bits" mapstructure:"key_bits"`
	MaxPathLength                 *int          `json:",omitempty" mapstructure:"max_path_length"`
	KeyUsageOld                   string        `json:"key_usage,omitempty"`
	KeyUsage                      []string      `json:"key_usage_list" mapstructure:"key_usage"`
	ExtKeyUsage                   []string      `json:"extended_key_usage_list" mapstructure:"extended_key_usage"`
	OUOld                         string        `json:"ou,omitempty"`
	OU                            []string      `json:"ou_list" mapstructure:"ou"`
	OrganizationOld               string        `json:"organization,omitempty"`
	Organization                  []string      `json:"organization_list" mapstructure:"organization"`
	Country                       []string      `json:"country" mapstructure:"country"`
	Locality                      []string      `json:"locality" mapstructure:"locality"`
	Province                      []string      `json:"province" mapstructure:"province"`
	StreetAddress                 []string      `json:"street_address" mapstructure:"street_address"`
	PostalCode                    []string      `json:"postal_code" mapstructure:"postal_code"`
	GenerateLease                 *bool         `json:"generate_lease,omitempty"`
	NoStore                       bool          `json:"no_store" mapstructure:"no_store"`
	RequireCN                     bool          `json:"require_cn" mapstructure:"require_cn"`
	AllowedOtherSANs              []string      `json:"allowed_other_sans" mapstructure:"allowed_other_sans"`
	AllowedSerialNumbers          []string      `json:"allowed_serial_numbers" mapstructure:"allowed_serial_numbers"`
	AllowedURISANs                []string      `json:"allowed_uri_sans" mapstructure:"allowed_uri_sans"`
	PolicyIdentifiers             []string      `json:"policy_identifiers" mapstructure:"policy_identifiers"`
	ExtKeyUsageOIDs               []string      `json:"ext_key_usage_oids" mapstructure:"ext_key_usage_oids"`
	BasicConstraintsValidForNonCA bool          `json:"basic_constraints_valid_for_non_ca" mapstructure:"basic_constraints_valid_for_non_ca"`
	NotBeforeDuration             time.Duration `json:"not_before_duration" mapstructure:"not_before_duration"`

	// Used internally for signing intermediates
	AllowExpirationPastCA bool
	Name                  string `json:"name"`

	CustomEnforcementConfig string `json:"custom_econfig"`

	// Venafi have this concept of zone/policy which is interchangeable
	// Vault has policy
	// we shall stick to zone so that it is clear
	// this is a venafi zone (path in a venafi platform)
	Zone                     string                             `json:"zone"`
	LastZoneUpdateTime       int64                              `json:"last_zone_update_time"`
	VExtKeyUsage             []x509.ExtKeyUsage                 `json:"ext_key_usage"`
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
}

func NewRoleEntry(b *backend, ctx context.Context, req *logical.Request, data *framework.FieldData) (*roleEntry, error) {

	name := data.Get("name").(string)

	entry := &roleEntry{
		MaxTTL:                        time.Duration(data.Get("max_ttl").(int)) * time.Second,
		TTL:                           time.Duration(data.Get("ttl").(int)) * time.Second,
		AllowLocalhost:                data.Get("allow_localhost").(bool),
		AllowedDomains:                data.Get("allowed_domains").([]string),
		AllowedDomainsTemplate:        data.Get("allowed_domains_template").(bool),
		AllowBareDomains:              data.Get("allow_bare_domains").(bool),
		AllowSubdomains:               data.Get("allow_subdomains").(bool),
		AllowGlobDomains:              data.Get("allow_glob_domains").(bool),
		AllowAnyName:                  data.Get("allow_any_name").(bool),
		EnforceHostnames:              data.Get("enforce_hostnames").(bool),
		AllowIPSANs:                   data.Get("allow_ip_sans").(bool),
		AllowedURISANs:                data.Get("allowed_uri_sans").([]string),
		ServerFlag:                    data.Get("server_flag").(bool),
		ClientFlag:                    data.Get("client_flag").(bool),
		CodeSigningFlag:               data.Get("code_signing_flag").(bool),
		EmailProtectionFlag:           data.Get("email_protection_flag").(bool),
		KeyType:                       data.Get("key_type").(string),
		KeyBits:                       data.Get("key_bits").(int),
		UseCSRCommonName:              data.Get("use_csr_common_name").(bool),
		UseCSRSANs:                    data.Get("use_csr_sans").(bool),
		KeyUsage:                      data.Get("key_usage").([]string),
		ExtKeyUsage:                   data.Get("ext_key_usage").([]string),
		ExtKeyUsageOIDs:               data.Get("ext_key_usage_oids").([]string),
		OU:                            data.Get("ou").([]string),
		Organization:                  data.Get("organization").([]string),
		Country:                       data.Get("country").([]string),
		Locality:                      data.Get("locality").([]string),
		Province:                      data.Get("province").([]string),
		StreetAddress:                 data.Get("street_address").([]string),
		PostalCode:                    data.Get("postal_code").([]string),
		GenerateLease:                 new(bool),
		NoStore:                       data.Get("no_store").(bool),
		RequireCN:                     data.Get("require_cn").(bool),
		AllowedSerialNumbers:          data.Get("allowed_serial_numbers").([]string),
		PolicyIdentifiers:             data.Get("policy_identifiers").([]string),
		BasicConstraintsValidForNonCA: data.Get("basic_constraints_valid_for_non_ca").(bool),
		NotBeforeDuration:             time.Duration(data.Get("not_before_duration").(int)) * time.Second,
		Name:                          name,
		CustomEnforcementConfig:       data.Get("custom_econfig").(string),
	}

	// we do not have a specific zone so we can calculate it
	updatedEntry, err := entry.updateFromVenafi(b, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return updatedEntry, nil
}

func (role *roleEntry) ComplianceChecks(req *logical.Request, isCA bool, csr *x509.CertificateRequest, cn string, ipAddresses, email, sans []string) error {

	if len(role.Zone) == 0 {
		if venafiPolicyDenyAll {
			return fmt.Errorf("zone data is nil. You need configure Venafi zone to proceed")
		} else {
			return nil
		}
	}

	if csr != nil {
		log.Printf("%s Checking CSR against zone %v", logPrefixEnforcement, role)
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
				log.Printf("%s invalid key in CSR", logPrefixEnforcement)
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
		log.Printf("%s Checking creation bundle against policy %v", logPrefixEnforcement, role)

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

func (role *roleEntry) checkCSR(isCA bool, csr *x509.CertificateRequest) error {
	if isCA {
		if len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || (len(csr.DNSNames) != 0 &&
			csr.DNSNames[0] != csr.Subject.CommonName) { //workaround for setting SAN if CA have normal domain in CN
			return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
		}
	} else {
		if !checkStringByRegexp(csr.Subject.CommonName, role.SubjectCNRegexes) {
			return fmt.Errorf("common name %s doesn't match regexps: %v", csr.Subject.CommonName, role.SubjectCNRegexes)
		}
		if !checkStringArrByRegexp(csr.EmailAddresses, role.EmailSanRegExs, true) {
			return fmt.Errorf("email SANs %v do not match regexps: %v", csr.EmailAddresses, role.EmailSanRegExs)
		}
		if !checkStringArrByRegexp(csr.DNSNames, role.DnsSanRegExs, true) {
			return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, role.DnsSanRegExs)
		}
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		if !checkStringArrByRegexp(ips, role.IpSanRegExs, true) {
			return fmt.Errorf("IP SANs %v do not match regexps: %v", ips, role.IpSanRegExs)
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
		return fmt.Errorf("organization %v doesn't match regexps: %v", csr.Subject.Organization, role.SubjectORegexes)
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
		pubkey, ok := csr.PublicKey.(*rsa.PublicKey)
		if ok {
			keyValid = checkKey("rsa", pubkey.Size()*8, "", role.AllowedKeyConfigurations)
		} else {
			log.Printf("%s invalid key in CSR", logPrefixEnforcement)
		}
	} else if csr.PublicKeyAlgorithm == x509.ECDSA {
		pubkey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if ok {
			keyValid = checkKey("ecdsa", 0, pubkey.Curve.Params().Name, role.AllowedKeyConfigurations)
		}
	}
	if !keyValid {
		return fmt.Errorf("key type is not allowed by Venafi")
	}
	return nil
}

func (role *roleEntry) checkCertCompliance(cert *x509.Certificate) (bool, error) {
	var req x509.CertificateRequest
	req.Subject = cert.Subject
	req.Extensions = cert.Extensions
	req.PublicKey = cert.PublicKey
	req.EmailAddresses = cert.EmailAddresses
	req.DNSNames = cert.DNSNames
	req.IPAddresses = cert.IPAddresses
	req.URIs = cert.URIs

	err := role.checkCSR(false, &req)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (role *roleEntry) ToResponseData() map[string]interface{} {
	type printKeyConfig struct {
		KeyType   string
		KeySizes  []int    `json:",omitempty"`
		KeyCurves []string `json:",omitempty"`
	}
	keyConfigs := make([]string, len(role.AllowedKeyConfigurations))
	for i, akc := range role.AllowedKeyConfigurations {
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
	responseData := map[string]interface{}{
		"ttl":                                int64(role.TTL.Seconds()),
		"max_ttl":                            int64(role.MaxTTL.Seconds()),
		"allow_localhost":                    role.AllowLocalhost,
		"allowed_domains":                    role.AllowedDomains,
		"allowed_domains_template":           role.AllowedDomainsTemplate,
		"allow_bare_domains":                 role.AllowBareDomains,
		"allow_token_displayname":            role.AllowTokenDisplayName,
		"allow_subdomains":                   role.AllowSubdomains,
		"allow_glob_domains":                 role.AllowGlobDomains,
		"allow_any_name":                     role.AllowAnyName,
		"enforce_hostnames":                  role.EnforceHostnames,
		"allow_ip_sans":                      role.AllowIPSANs,
		"server_flag":                        role.ServerFlag,
		"client_flag":                        role.ClientFlag,
		"code_signing_flag":                  role.CodeSigningFlag,
		"email_protection_flag":              role.EmailProtectionFlag,
		"use_csr_common_name":                role.UseCSRCommonName,
		"use_csr_sans":                       role.UseCSRSANs,
		"key_type":                           role.KeyType,
		"key_bits":                           role.KeyBits,
		"key_usage":                          role.KeyUsage,
		"ext_key_usage":                      role.ExtKeyUsage,
		"ext_key_usage_oids":                 role.ExtKeyUsageOIDs,
		"ou":                                 role.OU,
		"organization":                       role.Organization,
		"country":                            role.Country,
		"locality":                           role.Locality,
		"province":                           role.Province,
		"street_address":                     role.StreetAddress,
		"postal_code":                        role.PostalCode,
		"no_store":                           role.NoStore,
		"allowed_other_sans":                 role.AllowedOtherSANs,
		"allowed_serial_numbers":             role.AllowedSerialNumbers,
		"allowed_uri_sans":                   role.AllowedURISANs,
		"require_cn":                         role.RequireCN,
		"policy_identifiers":                 role.PolicyIdentifiers,
		"basic_constraints_valid_for_non_ca": role.BasicConstraintsValidForNonCA,
		"not_before_duration":                int64(role.NotBeforeDuration.Seconds()),
		"zone":                               role.Zone,
		"last_zone_update_time":              role.LastZoneUpdateTime,
		"subject_cn_regexes":                 role.SubjectCNRegexes,
		"subject_o_regexes":                  role.SubjectORegexes,
		"subject_ou_regexes":                 role.SubjectOURegexes,
		"subject_st_regexes":                 role.SubjectSTRegexes,
		"subject_l_regexes":                  role.SubjectLRegexes,
		"subject_c_regexes":                  role.SubjectCRegexes,
		"allowed_key_configurations":         keyConfigs,
		"dns_san_regexes":                    role.DnsSanRegExs,
		"ip_san_regexes":                     role.IpSanRegExs,
		"email_san_regexes":                  role.EmailSanRegExs,
		"uri_san_regexes":                    role.UriSanRegExs,
		"upn_san_regexes":                    role.UpnSanRegExs,
		"allow_wildcards":                    role.AllowWildcards,
		"allow_key_reuse":                    role.AllowKeyReuse,
	}
	if role.MaxPathLength != nil {
		responseData["max_path_length"] = role.MaxPathLength
	}
	if role.GenerateLease != nil {
		responseData["generate_lease"] = role.GenerateLease
	}
	return responseData
}

func (role *roleEntry) store(ctx context.Context, storage logical.Storage) error {
	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+role.Name, role)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, jsonEntry); err != nil {
		return err
	}

	return nil
}

func (role *roleEntry) ClientVenafi(b *backend, ctx context.Context, s *logical.Storage) (endpoint.Connector, string, error) {

	secret, zone, err := b.getconfig(ctx, s, role.CustomEnforcementConfig, role.Name)
	if err != nil {
		return nil, zone, err
	}

	connector, err := secret.getConnection(zone)
	return connector, zone, err
}

func (role *roleEntry) getZoneFromVenafi(b *backend, ctx context.Context, storage *logical.Storage) (policy *endpoint.Policy, err error) {
	log.Printf("%s Creating Venafi client", logPrefixEnforcement)

	cl, _, err := role.ClientVenafi(b, ctx, storage)
	if err != nil {
		return
	}
	log.Printf("%s Getting policy from Venafi endpoint", logPrefixEnforcement)

	policy, err = cl.ReadPolicyConfiguration()
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {

			cfg, err := b.getRoleBasedConfig(ctx, storage, role.CustomEnforcementConfig, role.Name)

			if err != nil {
				return nil, err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = synchronizedUpdateAccessToken(cfg, b, ctx, storage, role.CustomEnforcementConfig)

				if err != nil {
					return nil, err
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, _, err := role.ClientVenafi(b, ctx, storage)
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

func (b *backend) getPKIRoleEntry(ctx context.Context, storage logical.Storage, roleName string) (entry *roleEntry, err error) {
	//Update role since it's settings may be changed
	entry, err = b.getRole(ctx, storage, roleName)
	if err != nil {
		return entry, fmt.Errorf("Error getting role %v: %s\n", roleName, err)
	}
	return entry, nil
}

func (role *roleEntry) updateFromVenafi(b *backend, ctx context.Context, storage logical.Storage) (*roleEntry, error) {

	// grab the zone from Venafi
	zone, err := role.getZoneFromVenafi(b, ctx, &storage)
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
