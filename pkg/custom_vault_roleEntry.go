package pki

import (
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

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

func (r *roleEntry) ToResponseData() map[string]interface{} {
	type printKeyConfig struct {
		KeyType   string
		KeySizes  []int    `json:",omitempty"`
		KeyCurves []string `json:",omitempty"`
	}
	keyConfigs := make([]string, len(r.AllowedKeyConfigurations))
	for i, akc := range r.AllowedKeyConfigurations {
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
		"ttl":                                int64(r.TTL.Seconds()),
		"max_ttl":                            int64(r.MaxTTL.Seconds()),
		"allow_localhost":                    r.AllowLocalhost,
		"allowed_domains":                    r.AllowedDomains,
		"allowed_domains_template":           r.AllowedDomainsTemplate,
		"allow_bare_domains":                 r.AllowBareDomains,
		"allow_token_displayname":            r.AllowTokenDisplayName,
		"allow_subdomains":                   r.AllowSubdomains,
		"allow_glob_domains":                 r.AllowGlobDomains,
		"allow_any_name":                     r.AllowAnyName,
		"enforce_hostnames":                  r.EnforceHostnames,
		"allow_ip_sans":                      r.AllowIPSANs,
		"server_flag":                        r.ServerFlag,
		"client_flag":                        r.ClientFlag,
		"code_signing_flag":                  r.CodeSigningFlag,
		"email_protection_flag":              r.EmailProtectionFlag,
		"use_csr_common_name":                r.UseCSRCommonName,
		"use_csr_sans":                       r.UseCSRSANs,
		"key_type":                           r.KeyType,
		"key_bits":                           r.KeyBits,
		"key_usage":                          r.KeyUsage,
		"ext_key_usage":                      r.ExtKeyUsage,
		"ext_key_usage_oids":                 r.ExtKeyUsageOIDs,
		"ou":                                 r.OU,
		"organization":                       r.Organization,
		"country":                            r.Country,
		"locality":                           r.Locality,
		"province":                           r.Province,
		"street_address":                     r.StreetAddress,
		"postal_code":                        r.PostalCode,
		"no_store":                           r.NoStore,
		"allowed_other_sans":                 r.AllowedOtherSANs,
		"allowed_serial_numbers":             r.AllowedSerialNumbers,
		"allowed_uri_sans":                   r.AllowedURISANs,
		"require_cn":                         r.RequireCN,
		"policy_identifiers":                 r.PolicyIdentifiers,
		"basic_constraints_valid_for_non_ca": r.BasicConstraintsValidForNonCA,
		"not_before_duration":                int64(r.NotBeforeDuration.Seconds()),
		"zone":                               r.Zone,
		"last_zone_update_time":              r.LastZoneUpdateTime,
		"subject_cn_regexes":                 r.SubjectCNRegexes,
		"subject_o_regexes":                  r.SubjectORegexes,
		"subject_ou_regexes":                 r.SubjectOURegexes,
		"subject_st_regexes":                 r.SubjectSTRegexes,
		"subject_l_regexes":                  r.SubjectLRegexes,
		"subject_c_regexes":                  r.SubjectCRegexes,
		"allowed_key_configurations":         keyConfigs,
		"dns_san_regexes":                    r.DnsSanRegExs,
		"ip_san_regexes":                     r.IpSanRegExs,
		"email_san_regexes":                  r.EmailSanRegExs,
		"uri_san_regexes":                    r.UriSanRegExs,
		"upn_san_regexes":                    r.UpnSanRegExs,
		"allow_wildcards":                    r.AllowWildcards,
		"allow_key_reuse":                    r.AllowKeyReuse,
	}
	if r.MaxPathLength != nil {
		responseData["max_path_length"] = r.MaxPathLength
	}
	if r.GenerateLease != nil {
		responseData["generate_lease"] = r.GenerateLease
	}
	return responseData
}
