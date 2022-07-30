<#
	.SYNOPSIS
	Partial implementation of the AssetPanda REST API in PowerShell.
	
	.DESCRIPTION
	Allows searching, creating, updating, archiving, and deleting assets in AssetPanda using its REST API. 
	
	.NOTES
	Author: Matt Carras <mattcarras>
	
	[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
	
	.LINK
	https://github.com/mattcarras/AssetPandaPS
	
	.LINK
	https://api.assetpanda.com/api-docs
#>
	
function Format-ExceptionResponse {
	<#
		.SYNOPSIS
		Helper function to parse exceptions from Invoke-RestMethod.
		
		.DESCRIPTION
		Helper function to parse the response body from Invoke-RestMethod on [System.Net.WebException]. Returns an object with @{ Message, StatusCode, StatusDescription }
		
		.PARAMETER Exception
		Required. The thrown exception object.
		
		.Example
		PS> try { New-APObject -FieldValues @{SerialNumber="123456"; Name="AlreadyExists"} -Entity "Devices" } catch { Write-Host (Format-ExceptionResponse $_ | ConvertTo-Json -Depth 10) }
		{
			"Message":  {
							"errors":  [
										   {
											   "field_1":  [
															   "SerialNumber is not unique"
														   ],
											   "field_2":  [
															   "Name is not unique"
														   ]
										   }
									   ],
							"code":  2
						},
			"StatusDescription":  "Unprocessable Entity",
			"StatusCode":  422
		}
	#>
	param (
		[parameter(	Mandatory = $true, 
					Position = 0,
					ValueFromPipeline = $true,
					ValueFromPipelineByPropertyName=$true)]
		$Exception
	)
	Begin {
	}
	Process {
		$Message = $null
		if ($PSVersionTable.PSVersion.Major -lt 6) {
			if ($Exception.Exception.Response) {  
				$Reader = New-Object System.IO.StreamReader($Exception.Exception.Response.GetResponseStream())
				$Reader.BaseStream.Position = 0
				$Reader.DiscardBufferedData()
				$ResponseBody = $Reader.ReadToEnd()
				if ($ResponseBody.StartsWith('{')) {
					$ResponseBody = $ResponseBody | ConvertFrom-Json
				}
				$Message = $ResponseBody
			}
		}
		else {
			$Message = $Exception.ErrorDetails.Message
		}
		return @{
			Message = $Message
			StatusCode = $Exception.Exception.Response.StatusCode.value__ 
			StatusDescription = $Exception.Exception.Response.StatusDescription
		}
	}
	End {
	}
}

function Export-APCredentials {
	<#
		.SYNOPSIS
		Export AssetPanda API credentials to an XML file with encrypted values. ClientSecret and Password are encrypted under the current user account.
		
		.DESCRIPTION
		Export AssetPanda API credentials to an XML file with encrypted values. ClientSecret and Password are encrypted under the current user account. Returns the credentials on success.
		
		.PARAMETER File
        Required. The filename and path to export to.
		
		.PARAMETER ClientID
        Required. The ClientID specified in the AssetPanda environment.
		
		.PARAMETER ClientSecret
        Required. The ClientSecret specified in the AssetPanda environment.
		
		.PARAMETER Email
        Required. The Email address for the AssetPanda user account to be used by the API.
		
		.PARAMETER Password
        Required. The Password for the AssetPanda user account to be used by the API.
		
		.Example
		PS> Export-APCredentials -File "ap_creds.xml" -ClientID $ClientID -ClientSecret $ClientSecret -Email $email -Password $Password
	#>
	param (
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.IO.FileInfo]$File,
		
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ClientID,
		
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ClientSecret,

		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[mailaddress]$Email,

		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password
	)
	Begin {
	}
	Process {
		$creds = [PSCustomObject]@{ 
			ClientID=$ClientID
			ClientSecret=(ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)
			Email=$Email
			Password=(ConvertTo-SecureString -String $Password -AsPlainText -Force)
		}
		$creds | Export-Clixml $File
		return $creds
	}
	End {
	}
}

function Connect-APSession {
	<#
		.SYNOPSIS
		Connect to AssetPanda API and return OAuth authorization token in the form of "Bearer <token>".
		
		.DESCRIPTION
		Connect to AssetPanda API and return OAuth authorization token in the form of "Bearer <token>", storing the required token. Required for all other AssetPanda API calls.
		
		.PARAMETER CredXML
		Load previously exported credentials from given XML file (see Export-APCredentials). Mutually exclusive with other credential parameters.
		
		.PARAMETER ClientID
        The ClientID specified in the AssetPanda environment. Required unless the -CredXML parameter is given.
		
		.PARAMETER ClientSecret
        The ClientSecret specified in the AssetPanda environment. Required unless the -CredXML parameter is given.
		
		.PARAMETER Email
        The Email address for the AssetPanda user account to be used by the API. Required unless the -CredXML parameter is given.
		
		.PARAMETER Password
        The Password for the AssetPanda user account to be used by the API. Required unless the -CredXML parameter is given.
		
		.PARAMETER Device
		Reported Device name (Default: "Desktop")
		
		.PARAMETER AppVersion
		Reported AppVersion (Default: "1.0")
		
		.PARAMETER NoEntityMapping
		Skip querying and storing Entity Mapping.
		
		.NOTES
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $oauth = Connect-APSession -CredXML "creds.xml"
		
		PS> $oauth = Connect-APSession -ClientID $ClientID -ClientSecret $ClientSecret -Email $email -Password $Password
	#>
	param (
		[parameter(Mandatory=$true, ParameterSetName="CredXML")]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path $_ -PathType Leaf})]
		[System.IO.FileInfo]$CredXML,
		
		[parameter(Mandatory=$true, ParameterSetName="Default")]
		[ValidateNotNullOrEmpty()]
		[string]$ClientID,
		
		[parameter(Mandatory=$true, ParameterSetName="Default")]
		[ValidateNotNullOrEmpty()]
		[string]$ClientSecret,

		[parameter(Mandatory=$true, ParameterSetName="Default")]
		[ValidateNotNullOrEmpty()]
		[mailaddress]$Email,

		[parameter(Mandatory=$true, ParameterSetName="Default")]
		[ValidateNotNullOrEmpty()]
		[string]$Password,
		
		[parameter(Mandatory=$false)]
		[string]$Device = "Desktop",
		
		[parameter(Mandatory=$false)]
		[string]$AppVersion = "1.0",
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping
	)
	# Read from given XML file.
	if ($CredXML) {
		$creds = Import-Clixml $CredXML
		$ClientID = $creds.ClientID
		$ClientSecret = (New-Object PSCredential "user",$creds.ClientSecret).GetNetworkCredential().Password
		$Email = $creds.Email
		$Password = (New-Object PSCredential "user",$creds.Password).GetNetworkCredential().Password
	}
	# Compose REST request.
	$URL = "https://api.assetpanda.com:443/v2/session/token"
	$body = @{ 
		"app_version" = $AppVersion
		"client_id" = $ClientID
		"client_secret" = $ClientSecret
		"device" = $Device
		"email" = [string]$Email
		"password" = $Password
		"grant_type" = "password"
	}
	$results = Invoke-RestMethod -Method Post -Uri $URL -Body $body
	
	# Check if authentication is successfull.
	$oauth = $null
	if ([string]::IsNullOrEmpty($results.access_token)) {
		Write-Error "No valid Access Token returned"
	} else {
		# Make sure the first letter is capitalized in "Bearer"
		$oauth = (Get-Culture).TextInfo.ToTitleCase($results.token_type.tolower()) + " " + $results.access_token
		# Initialize the session data and store the token
		$script:_APSession = @{
			Authorization = $oauth
			EntityMap = $null
		}
	}
	
	return $oauth
}

function Get-APEntityMap {
	<#
		.SYNOPSIS
		Map entity field names defined in the end-user's AssetPanda environment to AP's internal field names.
		
		.DESCRIPTION
		Map entity field names defined in the end-user's AssetPanda environment to AP's internal field names. This allows the user to call functions and map the results with entity and field names like "Devices" and "Serial Number" instead of an entity ID or "field_11". This function is called internally if an EntityMap is not given as a parameter to functions that require it. The map is provided two-way with ["fields"] (defined name) and ["ap_fields"] (internal name). Built-in fields are also included by default in 1:1 mapping.
		
		.PARAMETER Entity
        Return the mapping for a specific entity.
		
		.PARAMETER ExcludeBuiltin
        Exclude mapping the built-in fields (which are mapped 1:1). This affects all future function calls when cached.
		
		.PARAMETER RefreshCache
        Refresh the built-in cache of entity mapping.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $EntityMap = Get-APEntityMap
	#>
	param (		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[switch]$ExcludeBuiltin,
		
		[parameter(Mandatory=$false)]
		[switch]$RefreshCache,
		
		[parameter(Mandatory=$false)]
		[ValidateScript({
			if ($_.Count -gt 0 -And -Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	# Construct headers if not given
	if ($Headers.Count -eq 0) {
		if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
			Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
		} else {
			$Headers = @{ Authorization = $script:_APSession["Authorization"] }
		}
	}
	# AP's built-in field names. TODO: Are these available for all entities?
	$BUILTINFIELDS = @("integ_ad_sid", "integ_audit_id", "gps_coordinates", "object_depreciation", "object_appreciation")
		
	# Return cached copy (if session initialized) unless -RefreshCache is given.
	$entitymap = $null
	if ($script:_APSession.Count -gt 0 -And $script:_APSession.EntityMap.Count -gt 0 -And -Not $RefreshCache) {
		$entitymap = $script:_APSession.EntityMap
	} else {
		$URL = "https://api.assetpanda.com:443/v2/entities"
		$entities = Invoke-RestMethod -Method Get -Uri $URL -Headers $Headers
		if ($entities.Count -gt 0) {
			$entitymap = @{}
			foreach ($e in $entities) {
				$entitymap[ $e.name ] = @{
					"id" = $e.id	# AP's internal ID
					"key" = $e.key
					fields = @{} # Matched by user-defined name in AP
					ap_fields = @{} # Matched by AP's internal field name (IE, field_1)
				}
				foreach ($field in $e.fields) {
					$entitymap[ $e.name ]["fields"][ $field.name ] = @{
						id = $field.id
						key = $field.key
					}
					$entitymap[ $e.name ]["ap_fields"][ $field.key ] = $field.name
				}
				# Include 1:1 mappings for built-in values such as integ_ad_sid, etc.
				if (-Not $ExcludeBuiltin) {
					foreach ($field in $BUILTINFIELDS) {
						$entitymap[ $e.name ]["fields"][ $field ] = @{
							key = $field
							id = $null
						}
						$entitymap[ $e.name ]["ap_fields"][ $field ] = $field
					}
				}
			}
			# Store in cache, if session initialized
			if ($script:_APSession.Count -gt 0) {
				$script:_APSession.EntityMap = $entitymap
			}
		}
	}
	# Return mapping for a specific entity, if given.
	if (-Not [string]::IsNullOrWhitespace($Entity)) {
		if (-Not $entitymap.ContainsKey($Entity)) {
			Write-Error "Invalid or unknown entity [$Entity]"
			$entitymap = $null
		} else {
			$entitymap = $entitymap[$Entity]
		}
	}
	return $entitymap
}

# Example object returned by AssetPanda's REST API:
<#
 totals                                              not_viewable objects
 ------                                              ------------ -------
 @{objects=1; group_totals=1000; offset=0; limit=50}            0 {@{id=123ab456cd789ef01gh23i45; display_name=FOO...
 
	id                     : 123ab456cd789ef01gh23i45
	display_name           : FOO
	display_with_secondary : FOO <FOOBAR>
	field_134              : 78901 (AutoID)
	field_11               : @{id=123456; display_name=Assigned}
	field_1                : FOO (Service Tag)
	field_3                : FOOBAR (Name)
	field_10               :
	field_16               : @{id=xxxxxxxxxxx; display_name=somebody@somewhere.com}
	field_8                : <Model>
	field_135              : <Department>
	field_2                : 2021-06-18
	field_136              : <Assigned Status>
	field_41               : 2024-09-16
	field_153              :
	field_29               : 2025-09-16
	field_152              :
	field_137              : PC
	field_151              : False
	field_144              : Laptop
	field_150              : True
	field_4                : API test (Notes)
	field_154              : <Asset Tag>
	field_156              : <SMBIOS GUID>
	field_157              : <MAC Address>
	field_155              : 2021-11-02
	field_158              : <LastLogonUser>
	field_159              : 2021-11-01
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
#>
function Search-APObject {
	<#
		.SYNOPSIS
		Return one or more object(s) from AssetPanda as a paginated list, given search parameters.
		
		.DESCRIPTION
		Return one or more object(s) from AssetPanda as a paginated list, given search parameters.
		
		.PARAMETER Field
		Filter the search by the given field name. Mutually exclusive with the -FieldValues and -GetAll parameters.
		
		.PARAMETER Value
		Required value of the -Field parameter, if given.
		
		.PARAMETER FieldValues
		Hashtable of "Field"="Value" pairs to filter results. Mutually exclusive with the -Field and -GetAll parameters.
		
		.PARAMETER Entity
		Required. Entity name or ID to process, e.g. "Devices". Assumed to be the internal EntityID if the -NoEntityMapping switch is given.
		
		.PARAMETER AllowPartialMatch
		Allow partial matching of given values. Default is false.
		
		.PARAMETER IncludeArchived
		Include archived objects in results. Default is false.
		
		.PARAMETER Offset
		Return paginated results starting from offset. Mainly useful when using -GetAll.
		
		.PARAMETER GetAll
		Return all objects found with no filtering. Use -Offset <int> to return results further in the paginated list.  Mutually exclusive with the -Field and -FieldValues parameters.
		
		.PARAMETER NoEntityMapping
		Disable Entity field/name mapping entirely, assuming everything given matches AssetPanda's internal IDs and field names.
		
		.PARAMETER EntityMap
        A hashtable mapping entity names to field names as returned by Get-APEntityMap. If not given the function is called internally unless the -NoEntityMapping switch is also given.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		AssetPanda's REST API limits the number of objects that can be returned from one API call to 50 at a time. Use the -Offset <int> parameter to paginate through the results.
		
		Any dates given must be in the same format defined in your AssetPanda environment.
		
		See the comments on this function for an example of the returned objects.
		
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $results = Search-APObject -Entity "Devices" -Field "Serial #" -Value "1234ABC"
		
		PS> $results = Search-APObject -Entity "Devices" -FieldValues @{"Serial #"="1234"; "Name"="Foo"} -AllowPartialMatch
		
		PS> $results = Search-APObject -Entity "Devices" -GetAll -Offset 51
	#>
	param (		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Field,
		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		
		[parameter(Mandatory=$true, ParameterSetName="FieldValues")]
		[ValidateNotNullOrEmpty()]
		[hashtable]$FieldValues,
		
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[switch]$AllowPartialMatch,
		
		[parameter(Mandatory=$false)]
		[switch]$IncludeArchived,
		
		[parameter(Mandatory=$false)]
		[int]$Offset,
		
		[parameter(Mandatory=$false, ParameterSetName="GetAll")]
		[switch]$GetAll,
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping,
		
		[parameter(Mandatory=$false)]
		[hashtable]$EntityMap,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	# Construct headers if not given
	if ($Headers.Count -eq 0) {
		if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
			Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
		} else {
			$Headers = @{ Authorization = $script:_APSession["Authorization"] }
		}
	}
	
	# Get EntityMap if needed, along with additional parameter checks.
	if (-Not $NoEntityMapping) {
		if (-Not $EntityMap) {
			$EntityMap = Get-APEntityMap -Headers $Headers -Entity $Entity
			if (-Not $EntityMap) {
				Write-Error "Get-APEntityMap returned invalid or empty EntityMap"
				return
			}
		}
	}
	
	$field_filters = $null
	if (-Not $GetAll) {
		# Setup field_filters (converting from names) and check validity.
		if ($FieldValues.Count -eq 0) {
			$fv = @{}
			$fv.add($Field, $Value)
		} else {
			$fv = $FieldValues
		}
		$field_filters = @{}
		foreach($field in $fv.Keys) {
			if ($NoEntityMapping) {
				$ap_field = $field
			} else {
				$ap_field = $EntityMap["fields"][$field]
				if (-Not $ap_field) {
					Write-Error "Invalid or unknown field name [${field}] for entity [${Entity}]"
					return
				} else {
					$ap_field = $ap_field["key"]
				}
			}
			$field_filters.Add($ap_field, $fv[$field])
		}
	}

	# Perform REST request.
	if ($NoEntityMapping) {
		$entityid = $entity
	} else {
		$entityid = $EntityMap.id
	}
	$URL = "https://api.assetpanda.com:443/v2/entities/${entityid}/search_objects"
	$body = @{ 
		"field_match" = if ($AllowPartialMatch) { "partial" } else { "full" }
		"ignore_invalid_field_keys" = "false"
	}
	if ($field_filters) {
		$body.Add("field_filters", $field_filters)
	}
	if ($Offset -ne $null) {
		$body.Add("offset", $Offset)
	}
	if ($IncludeArchived) {
		$body.Add("view_archived", "all")
	}
	$result = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -ContentType "application/json" -Body (ConvertTo-Json $body)			
	return $result	
}

function Get-APObject {
	<#
		.SYNOPSIS
		Returns an object from AssetPanda given its exact objectID.
		
		.DESCRIPTION
		Returns an object from AssetPanda given its exact objectID.
		
		.PARAMETER ObjectID
        Required. ID of object to return. Can be piped.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.Notes
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $result = Get-APObject -ObjectID "123abc"
	#>
	param (		
		[parameter(	Mandatory = $true, 
					Position = 0,
					ValueFromPipeline = $true,
					ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ObjectID,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	Begin {
		# Construct headers if not given
		if ($Headers.Count -eq 0) {
			if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
			} else {
				$Headers = @{ Authorization = $script:_APSession["Authorization"] }
			}
		}
	}
	Process {
		# Perform REST request.
		$URL = "https://api.assetpanda.com:443/v2/entity_objects/${ObjectID}"
		$result = Invoke-RestMethod -Method Get -Uri $URL -Headers $Headers -ContentType "application/json"
		return $result
	}
	End {
	}
}

function Get-APObjectsAll {
	<#
		.SYNOPSIS
		Returns all objects from AssetPanda for the given entity.
		
		.DESCRIPTION
		Returns all objects from AssetPanda for the given entity. Calls Search-APObject with -GetAll and -Offset in batches of 50 objects at time. May take some time to complete.
		
		.PARAMETER Entity
		Required. Entity name or ID to process, e.g. "Devices". Assumed to be the internal EntityID if the -NoEntityMapping switch is given.
		
		.PARAMETER IncludeArchived
		Include archived objects in results.
		
		.PARAMETER SleepSecs
		Number of seconds to sleep between each API call (Default: 5 seconds).
		
		.PARAMETER MaxRunMin
		Maximum number of minutes to spend collecting results (Default: 60 minutes).
		
		.PARAMETER UseArrayList
		Use and return [System.Collections.ArrayList] instead of appending each set of objects to an existing array. Might be faster.
		
		.PARAMETER NoEntityMapping
		Disable Entity field/name mapping entirely, assuming everything given matches AssetPanda's internal IDs and field names.
		
		.PARAMETER EntityMap
        A hashtable mapping entity names to field names as returned by Get-APEntityMap. If not given the function is called internally unless the -NoEntityMapping switch is also given.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.Notes
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $results = Get-APObjectsAll -Entity "Devices" -IncludeArchived
	#>
	param (
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[switch]$IncludeArchived,
		
		[parameter(Mandatory=$false)]
		[ValidateRange(0,86400)]
		[int]$SleepSecs = 5,		
		
		[parameter(Mandatory=$false)]
		[ValidateRange(0,525960)]
		[int]$MaxRunMin = 60,		
		
		[parameter(Mandatory=$false)]
		[switch]$UseArrayList,
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping,
		
		[parameter(Mandatory=$false)]
		[hashtable]$EntityMap,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	# Construct headers if not given
	if ($Headers.Count -eq 0) {
		if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
			Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
		} else {
			$Headers = @{ Authorization = $script:_APSession["Authorization"] }
		}
	}
	
	# Get EntityMap if needed, along with additional parameter checks.
	if (-Not $NoEntityMapping) {
		if (-Not $EntityMap) {
			$EntityMap = Get-APEntityMap -Headers $Headers -Entity $Entity
			if (-Not $EntityMap) {
				Throw "Get-APEntityMap returned invalid or empty EntityMap"
			}
		}
	}
		
	# Additional parameters for AP-GetObject
	$APGetObjParams = @{}
	if ($IncludeArchived) {
		$APGetObjParams.Add("IncludeArchived", $true)
	}

	# We're not sure how many items may be returned depending on parameters.
	if ($UseArrayList) {
		$all_objs = [System.Collections.ArrayList]@()
	} else {
		$all_objs = @()
	}
	$offset = 0
	$date_start = Get-Date
	while ($true) {
		$objs = Search-APObject -Headers $Headers -EntityMap $EntityMap -Entity $Entity -GetAll -Offset $offset @APGetObjParams
		if ($SleepSecs -gt 0) {
			Start-Sleep -s $SleepSecs
		}

		if ($objs -And $objs.objects -And $objs.objects.length) {
			if ($UseArrayList) {
				$all_objs.AddRange($objs.objects)
			} else {
				$all_objs += $objs.objects
			}
			if ($objs.objects.length -lt 50) {
				# break out of infinite loop
				break
			}
			$offset += 50
		} else {
			# break out of infinite loop
			break
		}
		
		# Check to see if this loop has gone on too long
		$ts = New-TimeSpan -Start $date_start -End (Get-Date)
		if ($ts.Minutes -gt $MaxRunMin) {
			Write-Error "Get-APObjectsAll has taken over $($ts.Minutes) minutes, aborting"
			break
		}
	}
	return $all_objs
}
	
function Update-APObject {
	<#
		.SYNOPSIS
		Update an object in AssetPanda given its ID, returning the updated object on success.
		
		.DESCRIPTION
		Update an object in AssetPanda given its ID, returning the updated object on success.
		
		.PARAMETER ObjectID
		Required. ID of object to update. Can be piped.
		
		.PARAMETER Field
		Field to update. Mutually exclusive with the -FieldValues parameter.
		
		.PARAMETER Value
		Required value of the -Field parameter, if given.
		
		.PARAMETER FieldValues
		Hashtable of "Field"="Value" pairs to update. Mutually exclusive with the -Field parameter.
		
		.PARAMETER Entity
		Entity name or ID to process, e.g. "Devices". Required for field mapping unless the -NoEntityMapping switch is given.
		
		.PARAMETER NoEntityMapping
		Disable Entity field/name mapping entirely, assuming everything given matches AssetPanda's internal IDs and field names.
		
		.PARAMETER EntityMap
		A hashtable mapping entity names to field names as returned by Get-APEntityMap. If not given the function is called internally unless the -NoEntityMapping switch is also given.
		
		.PARAMETER Headers
		Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		AssetPanda's REST API limits the number of objects that can be returned from one API call to 50 at a time. Use the -Offset <int> parameter to paginate through the results.
		
		Any dates given must be in the same format defined in your AssetPanda environment.
		
		See the comments on the AP-GetObject function for an example of a returned object.
		
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $result = Update-APObject -ObjectID "abc123456" -Field "Serial #" -Value "1234ABC" -Entity "Devices" 
	#>
	param (
		[parameter(	Mandatory = $true, 
					Position = 0,
					ValueFromPipeline = $true,
					ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ObjectID,
		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Field,
		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		
		[parameter(Mandatory=$true, ParameterSetName="FieldValues")]
		[ValidateNotNullOrEmpty()]
		[hashtable]$FieldValues,
		
		[parameter(Mandatory=$false)]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping,
		
		[parameter(Mandatory=$false)]
		[hashtable]$EntityMap,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	Begin {
		# Construct headers if not given
		if ($Headers.Count -eq 0) {
			if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
			} else {
				$Headers = @{ Authorization = $script:_APSession["Authorization"] }
			}
		}
		# Get EntityMap if needed, along with additional parameter checks.
		if (-Not $NoEntityMapping) {
			if (-Not $EntityMap) {
				$EntityMap = Get-APEntityMap -Headers $Headers -Entity $Entity
				if (-Not $EntityMap) {
					Throw "Get-APEntityMap returned invalid or empty EntityMap"
				}
			}
		}
	}
	Process {
		# Setup body with field keys and values, checking validity.
		$body = @{}
		if ($FieldValues.Count -eq 0) {
			$fv = @{}
			$fv.add($Field, $Value)
		} else {
			$fv = $FieldValues
		}
		foreach($field in $fv.Keys) {
			if ($NoEntityMapping) {
				$ap_field = $field
			} else {
				$ap_field = $EntityMap["fields"][$field]
			}
			if (-Not $ap_field) {
				Write-Error "Invalid or unknown field name [${field}] for entity [${Entity}]"
				return
			} else {
				$ap_field = $ap_field["key"]
			}
			$body.Add($ap_field, $fv[$field])
		}
				
		# Perform REST request.
		$URL = "https://api.assetpanda.com:443/v2/entity_objects/${ObjectID}"
		$result = Invoke-RestMethod -Method Patch -Uri $URL -Headers $Headers -ContentType "application/json" -Body (ConvertTo-Json $body)
		return $result
	}
	End {
	}
}

function New-APObject {
	<#
		.SYNOPSIS
		Create a new object in AssetPanda with the given values, returning the newly created object on success.
		
		.DESCRIPTION
		Create a new object in AssetPanda with the given values, returning the newly created object on success.
		
		.PARAMETER Field
		Field to set on creation of the new object. Fields not given will be set to defaults defined in the AssetPanda environment.
		
		.PARAMETER Value
		Required value of the -Field parameter, if given.
		
		.PARAMETER FieldValues
		Hashtable of "Field"="Value" pairs to set on object creation. Mutually exclusive with the -Field parameter.
		
		.PARAMETER Entity
		Required. Entity name or ID to process, e.g. "Devices". Assumed to be the internal EntityID if the -NoEntityMapping switch is given.
		
		.PARAMETER NoEntityMapping
		Disable Entity field/name mapping entirely, assuming everything given matches AssetPanda's internal IDs and field names.
		
		.PARAMETER EntityMap
        A hashtable mapping entity names to field names as returned by Get-APEntityMap. If not given the function is called internally unless the -NoEntityMapping switch is also given.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		See the comments on the AP-GetObject function for an example of a returned object.
		
		Any dates given must be in the same format defined in your AssetPanda environment.
		
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $result = New-APObject -FieldValues @{"Serial #"="123ABC"; "Name"="Foobar"; ...} -Entity "Devices" 
	#>
	param (		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Field,
		
		[parameter(Mandatory=$true, ParameterSetName="Field")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		
		[parameter(Mandatory=$true, ParameterSetName="FieldValues")]
		[ValidateNotNullOrEmpty()]
		[hashtable]$FieldValues,
		
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping,
		
		[parameter(Mandatory=$false)]
		[hashtable]$EntityMap,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	# Construct headers if not given
	if ($Headers.Count -eq 0) {
		if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
			Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
		} else {
			$Headers = @{ Authorization = $script:_APSession["Authorization"] }
		}
	}
	# Get EntityMap if needed, along with additional parameter checks.
	if (-Not $NoEntityMapping) {
		if (-Not $EntityMap) {
			$EntityMap = Get-APEntityMap -Headers $Headers -Entity $Entity
			if (-Not $EntityMap) {
				Throw "Get-APEntityMap returned invalid or empty EntityMap"
			}
		}
	}
	# Setup body with field keys and values, checking validity.
	$body = @{}
	if ($FieldValues.Count -eq 0) {
		$fv = @{}
		$fv.add($Field, $Value)
	} else {
		$fv = $FieldValues
	}
	foreach($field in $fv.Keys) {
		if ($NoEntityMapping) {
			$ap_field = $field
		} else {
			$ap_field = $EntityMap["fields"][$field]
			if (-Not $ap_field) {
				Write-Error "Invalid or unknown field name [${field}] for entity [${Entity}]"
				return
			} else {
				$ap_field = $ap_field["key"]
			}
		}
		$body.Add($ap_field, $fv[$field])
	}
	
	# Perform REST request.
	if ($NoEntityMapping) {
		$entityid = $entity
	} else {
		$entityid = $EntityMap.id
	}
	$URL = "https://api.assetpanda.com:443/v2/entities/${entityid}/objects"
	$result = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -ContentType "application/json" -Body (ConvertTo-Json $body)
	return $result
}

function Archive-APObject {
	<#
		.SYNOPSIS
		Archive/unarchive one or more object(s) in AssetPanda given the object ID(s).
		
		.DESCRIPTION
		Archive/unarchive one or more object(s) in AssetPanda given the object ID(s). Returns a message stating success or failure.
		
		.PARAMETER ObjectID
		Required. One or more object IDs to archive/unarchive. Can be piped.
		
		.PARAMETER Entity
		Required. Entity name or ID to process, e.g. "Devices". Assumed to be the internal EntityID if the -NoEntityMapping switch is given.
		
		.PARAMETER StopDate
		Set StopDate when archiving. Must be in the same format defined in your AssetPanda environment. If not given defaults to today's date. Ignored if -Unarchive switch is given.
		
		.PARAMETER Unarchive
		Unarchive the given object ID instead of archiving it.
		
		.PARAMETER NoEntityMapping
		Disable Entity field/name mapping entirely, assuming everything given matches AssetPanda's internal IDs and field names.
		
		.PARAMETER EntityMap
        A hashtable mapping entity names to field names as returned by Get-APEntityMap. If not given the function is called internally unless the -NoEntityMapping switch is also given.
		
		.PARAMETER Headers
        Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		See the comments on the AP-GetObject function for an example of a returned object.
		
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $result = Archive-APObject -ObjectID "123456abc" -Entity "Devices"
	#>
	param (
		[parameter(	Mandatory = $true, 
					Position = 0,
					ValueFromPipeline = $true,
					ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$ObjectID,
		
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Entity,
		
		[parameter(Mandatory=$false)]
		[ValidateScript({Get-Date($_) -is [DateTime]})]
		[string]$StopDate,
		
		[parameter(Mandatory=$false)]
		[switch]$Unarchive,
		
		[parameter(Mandatory=$false)]
		[switch]$NoEntityMapping,
		
		[parameter(Mandatory=$false)]
		[hashtable]$EntityMap,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	Begin {
		# Construct headers if not given
		if ($Headers.Count -eq 0) {
			if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
			} else {
				$Headers = @{ Authorization = $script:_APSession["Authorization"] }
			}
		}
		# Get EntityMap if needed, along with additional parameter checks.
		if (-Not $NoEntityMapping) {
			if (-Not $EntityMap) {
				$EntityMap = Get-APEntityMap -Headers $Headers -Entity $Entity
				if (-Not $EntityMap) {
					Throw "Get-APEntityMap returned invalid or empty EntityMap"
				}
			}
		}
	}
	Process {
		# The passed objectIDs must be an array for when they're converted to Json.
		if ($ObjectID -isnot [array]) {
			$ObjectID = @($ObjectID)
		}
		if ($NoEntityMapping) {
			$entityid = $entity
		} else {
			$entityid = $EntityMap.id
		}
		$URL = "https://api.assetpanda.com:443/v2/entities/${entityid}"
		$body = @{ "object_ids" = $ObjectID }
		if ($Unarchive) {
			if ($StopDate) {
				Write-Warning "StopDate ignored with -Unarchive switch"
			}
			$URL += "/unarchive_objects"
		} else {
			$URL += "/archive_objects"
			if ($StopDate) {
				$body.Add("stop_date",$StopDate)
			}
		}
		$result = Invoke-RestMethod -Method Post -Uri $URL -Headers $Headers -ContentType "application/json" -Body (ConvertTo-Json $body)
		return $result
	}
	End {
	}
}

function Remove-APObject {
	<#
		.SYNOPSIS
		Delete an object in AssetPanda given its ID, returning the object on success.
		
		.DESCRIPTION
		Delete an object in AssetPanda given its ID, returning the object on success.
		
		.PARAMETER ObjectID
		Required. ID of object to delete. Can be piped.
		
		.PARAMETER Comment
		Submit comment with deletion request. Required if "require_comment_on_object_delete" is set to "true" in the target AssetPanda environment.
		
		.PARAMETER Headers
		Override the headers for the Invoke-RestMethod call. Must contain the ['Authorization'] OAuth token returned from Connect-APSession.
		
		.NOTES
		[System.Net.WebException] is thrown by the system on error. The Format-ExceptionResponse function can parse the resulting exception into a more readable format. See Format-ExceptionResponse for an example of a returned error.
		
		.Example
		PS> $result = Remove-APObject -ObjectID "abc123456"
	#>
	param (
		[parameter(	Mandatory = $true, 
					Position = 0,
					ValueFromPipeline = $true,
					ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ObjectID,
		
		[parameter(Mandatory=$false)]
		[string]$Comment,
		
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			if (-Not [string]::IsNullOrWhitespace($_["Authorization"])) {
				$true
			} else {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key."
			}
		})]
		[hashtable]$Headers
	)
	Begin {
		# Construct headers if not given
		if ($Headers.Count -eq 0) {
			if ($script:_APSession.Count -eq 0 -OR [string]::IsNullOrWhitespace($script:_APSession["Authorization"])) {
				Throw [System.Management.Automation.ValidationMetadataException] "Missing or empty ['Authorization'] key for OAuth. Have you called Connect-APSession?"
			} else {
				$Headers = @{ Authorization = $script:_APSession["Authorization"] }
			}
		}
	}
	Process {
		$body = @{}
		if (-Not [string]::IsNullOrWhitespace($Comment)) {
			$body.Add("delete_comment",$Comment)
		}
				
		# Perform REST request.
		$URL = "https://api.assetpanda.com:443/v2/entity_objects/${ObjectID}"
		$result = Invoke-RestMethod -Method Delete -Uri $URL -Headers $Headers -ContentType "application/json" -Body (ConvertTo-Json $body)
		return $result
	}
	End {
	}
}