# AssetPandaPS
Powershell API Implementation for AssetPanda's RESTful API

All functions have been tested working successfully in our AssetPanda environment for syncing assets with SCCM and AD. Your mileage may vary.

## Implemented Functions
Use `get-help <Function>` for more information about each function (e.g. `get-help Connect-APSession`). You must call the script at least once to register the function help.

- `Connect-APSession`
- `Export-APCredentials`
- `Get-APEntityMap`
- `Search-APObject`
- `Get-APObject`
- `Get-APObjectsAll`
- `Update-APObject`
- `New-APObject`
- `Archive-APObject`
- `Remove-APObject`
- `Format-ExceptionResponse`

## Usage
`Connect-APSession` is used for OAuth authorization and to initialize the script's session variable. Use `Export-APCredentials` to export your credentials to an XML file with encrypted values. You can then give call `Connect-APSession` with the saved credentials using the `-CredXML <filepath>` parameter.

```
. .\AssetPandaPS.ps1
Connect-APSession -CredXML "mycreds.xml" | Out-Null
try {
	# Return all objects for entity with user-defined name of "Devices"
	$objs = Get-APObjectsAll -Entity "Devices"
} catch [System.Net.WebException] {
	# Write out the exception in a more readable format
	Write-Host (Format-ExceptionResponse $_ | ConvertTo-Json -Depth 10)
}
```

## Field Name Mapping
Returned objects will have their internal field names within AssetPanda, IE "field_1" instead of whatever its user-defined value may be. The `Get-APEntityMap` function provides a two-way mapping of user-defined fields ("fields") and AssetPanda's internal field names ("ap_fields"). Both include a 1:1 mapping for known built-in fields, some of which are only writable by the REST API (such as "integ_ad_sid"). Example:
```
PS> Get-APObject -ObjectID "123ab456cd789ef01gh23i45"
{
	id                     : 123ab456cd789ef01gh23i45
	display_name           : FOO
	display_with_secondary : FOO <FOOBAR>
	field_7                : 78901 (AutoID)
	field_4                : @{id=123456; display_name=Assigned}
	field_1                : FOO (Service Tag)
	field_3                : FOOBAR (Name)
	field_5                : @{id=xxxxxxxxxxx; display_name=somebody@somewhere.com}
	field_6                : <Model Foobar>
	field_2                : 2021-06-18
	integ_ad_sid           :
	integ_audit_id         :
	gps_coordinates        : {}
	object_depreciation    : False
	object_appreciation    : False
	share_url              : https://login.assetpanda.com/devices/123ab456cd789ef01gh23i45
	created_at             : 2021-08-31T17:51:56.547Z
	updated_at             : 2021-11-04T12:02:38.689Z
	sync_updated_at        :
	is_editable            : True
	is_deletable           : True
	object_version_ids     : 8
	has_audit_history      : False
	default_attachment     :
	is_locked              : False
	locked_details         :
	is_archived            : False
	entity                 : @{id=12345; key=devices}
}

PS> $entitymap = Get-APEntityMap -Entity "Devices"
PS> $entitymap["fields"]["Service Tag"].key
field_1
```

## API Limits
AssetPanda's REST API returns a paginated list of results by default, limited to 50 objects at a time. Use the `-Offset <#>` parameter with `Search-APObject` to paginate through the results, or `Get-APObjectsAll` if you want all objects. Use the `-IncludeArchive` switch if you want to include archived objects in the results.

Double-check with AssetPanda support for your environment's API limits. Last I checked our environment was 400 calls per 3 minutes.

## TODO
Convert into PowerShell module and upload to PSGallery.

Upload examples of syncing assets exported from SCCM and AD.

## Links
AssetPanda API reference: https://api.assetpanda.com/api-docs/v2
