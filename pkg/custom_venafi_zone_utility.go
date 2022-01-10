package pki

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) updateRoleEntryFromVenafi(ctx context.Context, storage logical.Storage, role *roleEntry) (*roleEntry, error) {

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
