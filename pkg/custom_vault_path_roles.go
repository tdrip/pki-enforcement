package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"backend": {
				Type:        framework.TypeString,
				Description: "Backend Type",
			},

			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `The lease duration if no specific lease duration is
requested. The lease duration controls the expiration
of certificates issued by this backend. Defaults to
the value of max_ttl.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "TTL",
				},
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lease duration",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Max TTL",
				},
			},

			"allow_localhost": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `Whether to allow "localhost" as a valid common
name in a request`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: true,
				},
			},

			"allowed_domains": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, clients can request certificates for
subdomains directly beneath these domains, including
the wildcard subdomains. See the documentation for more
information. This parameter accepts a comma-separated 
string or list of domains.`,
			},
			"allowed_domains_template": {
				Type: framework.TypeBool,
				Description: `If set, Allowed domains can be specified using identity template policies.
				Non-templated domains are also permitted.`,
				Default: false,
			},
			"allow_bare_domains": {
				Type: framework.TypeBool,
				Description: `If set, clients can request certificates
for the base domains themselves, e.g. "example.com".
This is a separate option as in some cases this can
be considered a security threat.`,
			},

			"allow_subdomains": {
				Type: framework.TypeBool,
				Description: `If set, clients can request certificates for
subdomains of the CNs allowed by the other role options,
including wildcard subdomains. See the documentation for
more information.`,
			},

			"allow_glob_domains": {
				Type: framework.TypeBool,
				Description: `If set, domains specified in "allowed_domains"
can include glob patterns, e.g. "ftp*.example.com". See
the documentation for more information.`,
			},

			"allow_any_name": {
				Type: framework.TypeBool,
				Description: `If set, clients can request certificates for
any CN they like. See the documentation for more
information.`,
			},

			"enforce_hostnames": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, only valid host names are allowed for
CN and SANs. Defaults to true.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: true,
				},
			},

			"allow_ip_sans": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, IP Subject Alternative Names are allowed.
Any valid IP is accepted.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Allow IP Subject Alternative Names",
					Value: true,
				},
			},

			"allowed_uri_sans": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, an array of allowed URIs to put in the URI Subject Alternative Names.
Any valid URI is accepted, these values support globbing.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Allowed URI Subject Alternative Names",
				},
			},

			"allowed_other_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: `If set, an array of allowed other names to put in SANs. These values support globbing and must be in the format <oid>;<type>:<value>. Currently only "utf8" is a valid type. All values, including globbing values, must use this syntax, with the exception being a single "*" which allows any OID and any value (but type must still be utf8).`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Allowed Other Subject Alternative Names",
				},
			},

			"allowed_serial_numbers": {
				Type:        framework.TypeCommaStringSlice,
				Description: `If set, an array of allowed serial numbers to put in Subject. These values support globbing.`,
			},

			"server_flag": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, certificates are flagged for server auth use.
Defaults to true.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: true,
				},
			},

			"client_flag": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, certificates are flagged for client auth use.
Defaults to true.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: true,
				},
			},

			"code_signing_flag": {
				Type: framework.TypeBool,
				Description: `If set, certificates are flagged for code signing
use. Defaults to false.`,
			},

			"email_protection_flag": {
				Type: framework.TypeBool,
				Description: `If set, certificates are flagged for email
protection use. Defaults to false.`,
			},

			"key_type": {
				Type:    framework.TypeString,
				Default: "rsa",
				Description: `The type of key to use; defaults to RSA. "rsa"
and "ec" are the only valid values.`,
				AllowedValues: []interface{}{"rsa", "ec"},
			},

			"key_bits": {
				Type:    framework.TypeInt,
				Default: 2048,
				Description: `The number of bits to use. You will almost
certainly want to change this if you adjust
the key_type.`,
			},

			"key_usage": {
				Type:    framework.TypeCommaStringSlice,
				Default: []string{"DigitalSignature", "KeyAgreement", "KeyEncipherment"},
				Description: `A comma-separated string or list of key usages (not extended
key usages). Valid values can be found at
https://golang.org/pkg/crypto/x509/#KeyUsage
-- simply drop the "KeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: "DigitalSignature,KeyAgreement,KeyEncipherment",
				},
			},

			"ext_key_usage": {
				Type:    framework.TypeCommaStringSlice,
				Default: []string{},
				Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Extended Key Usage",
				},
			},

			"ext_key_usage_oids": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma-separated string or list of extended key usage oids.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Extended Key Usage OIDs",
				},
			},

			"use_csr_common_name": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, when used with a signing profile,
the common name in the CSR will be used. This
does *not* include any requested Subject Alternative
Names. Defaults to true.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Use CSR Common Name",
					Value: true,
				},
			},

			"use_csr_sans": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, when used with a signing profile,
the SANs in the CSR will be used. This does *not*
include the Common Name (cn). Defaults to true.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Use CSR Subject Alternative Names",
					Value: true,
				},
			},

			"ou": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, OU (OrganizationalUnit) will be set to
this value in certificates issued by this role.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Organizational Unit",
				},
			},

			"organization": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, O (Organization) will be set to
this value in certificates issued by this role.`,
			},

			"country": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Country will be set to
this value in certificates issued by this role.`,
			},

			"locality": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Locality will be set to
this value in certificates issued by this role.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Locality/City",
				},
			},

			"province": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Province will be set to
this value in certificates issued by this role.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Province/State",
				},
			},

			"street_address": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Street Address will be set to
this value in certificates issued by this role.`,
			},

			"postal_code": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Postal Code will be set to
this value in certificates issued by this role.`,
			},

			"generate_lease": {
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false". Certificates can be added to the CRL by
"vault revoke <lease_id>" when certificates are associated with leases.  It can
also be done using the "pki/revoke" endpoint. However, when lease generation is
disabled, invoking "pki/revoke" would be the only way to add the certificates
to the CRL.  When large number of certificates are generated with long
lifetimes, it is recommended that lease generation be disabled, as large amount of
leases adversely affect the startup time of Vault.`,
			},

			"no_store": {
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will not be stored in the
storage backend. This can improve performance when issuing large numbers of 
certificates. However, certificates issued in this way cannot be enumerated
or revoked, so this option is recommended only for certificates that are
non-sensitive, or extremely short-lived. This option implies a value of "false"
for "generate_lease".`,
			},

			"require_cn": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: `If set to false, makes the 'common_name' field optional while generating a certificate.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Require Common Name",
				},
			},

			"policy_identifiers": {
				Type:        framework.TypeCommaStringSlice,
				Description: `A comma-separated string or list of policy oids.`,
			},

			"basic_constraints_valid_for_non_ca": {
				Type:        framework.TypeBool,
				Description: `Mark Basic Constraints valid when issuing non-CA certificates.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Basic Constraints Valid for Non-CA",
				},
			},
			"not_before_duration": {
				Type:        framework.TypeDurationSecond,
				Default:     30,
				Description: `The duration before now the cert needs to be created / signed.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Value: 30,
				},
			},

			"custom_econfig": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "The name of custom enforcement configuration " + enforcementConfigPath + "[name]. If not provided " + enforcementConfigPath + defaultEnforcementName + " will be used",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleCreate,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	// Migrate existing saved entries and save back if changed
	modified := false
	if len(result.DeprecatedTTL) == 0 && len(result.Lease) != 0 {
		result.DeprecatedTTL = result.Lease
		result.Lease = ""
		modified = true
	}
	if result.TTL == 0 && len(result.DeprecatedTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedTTL)
		if err != nil {
			return nil, err
		}
		result.TTL = parsed
		result.DeprecatedTTL = ""
		modified = true
	}
	if len(result.DeprecatedMaxTTL) == 0 && len(result.LeaseMax) != 0 {
		result.DeprecatedMaxTTL = result.LeaseMax
		result.LeaseMax = ""
		modified = true
	}
	if result.MaxTTL == 0 && len(result.DeprecatedMaxTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedMaxTTL)
		if err != nil {
			return nil, err
		}
		result.MaxTTL = parsed
		result.DeprecatedMaxTTL = ""
		modified = true
	}
	if result.AllowBaseDomain {
		result.AllowBaseDomain = false
		result.AllowBareDomains = true
		modified = true
	}
	if result.AllowedDomainsOld != "" {
		result.AllowedDomains = strings.Split(result.AllowedDomainsOld, ",")
		result.AllowedDomainsOld = ""
		modified = true
	}
	if result.AllowedBaseDomain != "" {
		found := false
		for _, v := range result.AllowedDomains {
			if v == result.AllowedBaseDomain {
				found = true
				break
			}
		}
		if !found {
			result.AllowedDomains = append(result.AllowedDomains, result.AllowedBaseDomain)
		}
		result.AllowedBaseDomain = ""
		modified = true
	}

	// Upgrade generate_lease in role
	if result.GenerateLease == nil {
		// All the new roles will have GenerateLease always set to a value. A
		// nil value indicates that this role needs an upgrade. Set it to
		// `true` to not alter its current behavior.
		result.GenerateLease = new(bool)
		*result.GenerateLease = true
		modified = true
	}

	// Upgrade key usages
	if result.KeyUsageOld != "" {
		result.KeyUsage = strings.Split(result.KeyUsageOld, ",")
		result.KeyUsageOld = ""
		modified = true
	}

	// Upgrade OU
	if result.OUOld != "" {
		result.OU = strings.Split(result.OUOld, ",")
		result.OUOld = ""
		modified = true
	}

	// Upgrade Organization
	if result.OrganizationOld != "" {
		result.Organization = strings.Split(result.OrganizationOld, ",")
		result.OrganizationOld = ""
		modified = true
	}

	if modified && (b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		jsonEntry, err := logical.StorageEntryJSON("role/"+n, &result)
		if err != nil {
			return nil, err
		}
		if err := s.Put(ctx, jsonEntry); err != nil {
			// Only perform upgrades on replication primary
			if !strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return nil, err
			}
		}
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	//Cleanup Venafi import if defined
	roleName := data.Get("name").(string)
	b.cleanupImportToTPP(roleName, ctx, req)
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var err error

	entry, err := NewRoleEntry(b, ctx, req, data)
	if err != nil {
		return logical.ErrorResponse("New Role failed with: %v", err), err
	}

	allowedOtherSANs := data.Get("allowed_other_sans").([]string)
	switch {
	case len(allowedOtherSANs) == 0:
	case len(allowedOtherSANs) == 1 && allowedOtherSANs[0] == "*":
	default:
		_, err := parseOtherSANs(allowedOtherSANs)
		if err != nil {
			return logical.ErrorResponse(fmt.Errorf("error parsing allowed_other_sans: %w", err).Error()), nil
		}
	}
	entry.AllowedOtherSANs = allowedOtherSANs

	// no_store implies generate_lease := false
	if entry.NoStore {
		*entry.GenerateLease = false
	} else {
		*entry.GenerateLease = data.Get("generate_lease").(bool)
	}

	if entry.KeyType == "rsa" && entry.KeyBits < 2048 {
		return logical.ErrorResponse("RSA keys < 2048 bits are unsafe and not supported"), nil
	}

	if entry.MaxTTL > 0 && entry.TTL > entry.MaxTTL {
		return logical.ErrorResponse(
			`"ttl" value must be less than "max_ttl" value`,
		), nil
	}

	if err := certutil.ValidateKeyTypeLength(entry.KeyType, entry.KeyBits); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(entry.ExtKeyUsageOIDs) > 0 {
		for _, oidstr := range entry.ExtKeyUsageOIDs {
			_, err := certutil.StringToOid(oidstr)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%q could not be parsed as a valid oid for an extended key usage", oidstr)), nil
			}
		}
	}

	if len(entry.PolicyIdentifiers) > 0 {
		for _, oidstr := range entry.PolicyIdentifiers {
			_, err := certutil.StringToOid(oidstr)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%q could not be parsed as a valid oid for a policy identifier", oidstr)), nil
			}
		}
	}

	err = entry.store(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func parseKeyUsages(input []string) int {
	var parsedKeyUsages x509.KeyUsage
	for _, k := range input {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "digitalsignature":
			parsedKeyUsages |= x509.KeyUsageDigitalSignature
		case "contentcommitment":
			parsedKeyUsages |= x509.KeyUsageContentCommitment
		case "keyencipherment":
			parsedKeyUsages |= x509.KeyUsageKeyEncipherment
		case "dataencipherment":
			parsedKeyUsages |= x509.KeyUsageDataEncipherment
		case "keyagreement":
			parsedKeyUsages |= x509.KeyUsageKeyAgreement
		case "certsign":
			parsedKeyUsages |= x509.KeyUsageCertSign
		case "crlsign":
			parsedKeyUsages |= x509.KeyUsageCRLSign
		case "encipheronly":
			parsedKeyUsages |= x509.KeyUsageEncipherOnly
		case "decipheronly":
			parsedKeyUsages |= x509.KeyUsageDecipherOnly
		}
	}

	return int(parsedKeyUsages)
}

func parseExtKeyUsages(role *roleEntry) certutil.CertExtKeyUsage {
	var parsedKeyUsages certutil.CertExtKeyUsage

	if role.ServerFlag {
		parsedKeyUsages |= certutil.ServerAuthExtKeyUsage
	}

	if role.ClientFlag {
		parsedKeyUsages |= certutil.ClientAuthExtKeyUsage
	}

	if role.CodeSigningFlag {
		parsedKeyUsages |= certutil.CodeSigningExtKeyUsage
	}

	if role.EmailProtectionFlag {
		parsedKeyUsages |= certutil.EmailProtectionExtKeyUsage
	}

	for _, k := range role.ExtKeyUsage {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "any":
			parsedKeyUsages |= certutil.AnyExtKeyUsage
		case "serverauth":
			parsedKeyUsages |= certutil.ServerAuthExtKeyUsage
		case "clientauth":
			parsedKeyUsages |= certutil.ClientAuthExtKeyUsage
		case "codesigning":
			parsedKeyUsages |= certutil.CodeSigningExtKeyUsage
		case "emailprotection":
			parsedKeyUsages |= certutil.EmailProtectionExtKeyUsage
		case "ipsecendsystem":
			parsedKeyUsages |= certutil.IpsecEndSystemExtKeyUsage
		case "ipsectunnel":
			parsedKeyUsages |= certutil.IpsecTunnelExtKeyUsage
		case "ipsecuser":
			parsedKeyUsages |= certutil.IpsecUserExtKeyUsage
		case "timestamping":
			parsedKeyUsages |= certutil.TimeStampingExtKeyUsage
		case "ocspsigning":
			parsedKeyUsages |= certutil.OcspSigningExtKeyUsage
		case "microsoftservergatedcrypto":
			parsedKeyUsages |= certutil.MicrosoftServerGatedCryptoExtKeyUsage
		case "netscapeservergatedcrypto":
			parsedKeyUsages |= certutil.NetscapeServerGatedCryptoExtKeyUsage
		}
	}

	return parsedKeyUsages
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRoleHelpSyn = `Manage the roles that can be created with this backend.`

const pathRoleHelpDesc = `This path lets you manage the roles that can be created with this backend.`
