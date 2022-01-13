# pki-enforcement
A Vault plugin that will operate with role enforcement based around the TPP system


# Setup

## Enable plugin
Set the SHA256 hash to authorize the plugin and then turn on the plugin.
(Note that the pki-enforcement plugin should be in the vault "plugins" directory)

```
vault write sys/plugins/catalog/secret/pki-enforcement sha_256="da92334c37b718db2f018289d3522a09289c8053e33526983ace3065123993e8" command="pki-enforcement"

vault secrets enable -path=pkie -plugin-name=pki-enforcement plugin
```

## Enable Venafi connection path

We have to provide a zone for the vcert client - it's nottechnically needed however i'd recommend a "fall back" zone so that if configuration is wrong this zone is used instead

A custom name can be used instead of tpp (aka tpp)

This will save when connection to TPP is successful

```

vault write pkie/venafi/tpp url="<URL to Venafi API>" trust_bundle_file="<path to trust bundle for Venafi API>" access_token="" refresh_token="" zone="<fallback zone>"

```

## Setup enforcement configuration 

This sets the default enforcement configuration to the venafi connection (tpp) and the zone for placement

This path can have a custom name (not default) and a different tpp connection can be set 

```

vault write pkie/enforcement-config/default venafi_secret="<TPP Configuration Name>" parent_zone="<Placement Zone>"

```


