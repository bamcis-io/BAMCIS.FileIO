Function Set-FileSecurity {
	<#
		.SYNOPSIS
			Sets permissions on a file or directory.

		.DESCRIPTION
			Will add or replace the supplied rules to the specified file or directory. The default behavior is that the rules are just added to the current ACL of the object.

		.PARAMETER Path
			The path to the file to set permissions on.

		.PARAMETER Rules
			An array of File Access Rules to apply to the path.

		.PARAMETER ReplaceAllRules
			Indictates if all permissions on the path should be replaced with these.

		.PARAMETER ReplaceNonInherited
			Replaces all existing rules that are not inherited from a parent directory.

		.PARAMETER ReplaceRulesForUser
			Indicates if the supplied rules should replace existing rules for matching users. For example, if the Rules parameter has a Full Control rule for System and a Read rules for 
			Administrators, existing rules for System and Administrators would be removed and replaced with the new rules.

		.PARAMETER AddIfNotPresent
			Add the rules if they do not already exist on the path. The rules are matched based on all properties including FileSystemRights, PropagationFlags, InheritanceFlags, etc.

		.PARAMETER ForceChildInheritance
			Indicates if all permissions of child items should have their permissions replaced with the parent if the target is a directory.

		.PARAMETER EnableChildInheritance
			Indicates that child items should have inheritance enabled, but will still preserve existing permissions. This parameter is ignored if ForceChildInheritance is specified.

		.PARAMETER ResetInheritance
			Indicates that all explicitly set permissions will be removed from the path and inheritance from its parent will be forced.

        .EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test.txt" -Rules $Rules

			Creates the rule set on the test.txt file.

		.EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test" -ResetInheritance

			Resets inherited permissions on the c:\test directory.

		.EXAMPLE
			PS C:\>Set-Permissions -Path "c:\test" -Rules $Rules -ReplaceAllRules -ForceChildInheritance

			Replaces all existing rules on the c:\test directory with the newly supplied rules and forces child objects to inherit those permissions. This removes existing explicit permissions on child objects.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2017
	#>

	[CmdletBinding(DefaultParameterSetName = "Add")]
	[Alias("Set-FilePermissions")]
	[OutputType()]
    Param 
    (
        [Parameter(Position=0,Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [System.String]$Path,

		[Parameter(ParameterSetName = "ReplaceAll")]
		[Parameter(ParameterSetName = "Replace")]
		[Parameter(ParameterSetName = "Add")]
		[Parameter(ParameterSetName = "AddIfNotPresent")]
		[Parameter(ParameterSetName = "ReplaceNonInherited")]
		[Parameter(ParameterSetName = "AddIfNotPresentAndReplace")]
		[Alias("Rules")]
		[ValidateNotNull()]
        [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules,

		[Parameter(ParameterSetName = "ReplaceAll")]
		[Parameter(ParameterSetName = "Replace")]
		[Parameter(ParameterSetName = "Add")]
		[Parameter(ParameterSetName = "AddIfNotPresent")]
		[Parameter(ParameterSetName = "ReplaceNonInherited")]
		[Parameter(ParameterSetName = "AddIfNotPresentAndReplace")]
		[ValidateNotNull()]
		[System.Security.AccessControl.FileSystemAuditRule[]]$AuditRules,

		[Parameter(ParameterSetName = "ReplaceAll")]
		[Switch]$ReplaceAllRules,

		[Parameter(ParameterSetName = "ReplaceNonInherited")]
		[Switch]$ReplaceNonInheritedRules,

		[Parameter(ParameterSetName = "Replace")]
		[Switch]$ReplaceRulesForUser,

		[Parameter(ParameterSetName = "AddIfNotPresent")]
		[Switch]$AddIfNotPresent,

		[Parameter(ParameterSetName = "AddIfNotPresentAndReplace")]
		[Switch]$AddIfNotPresentAndReplace,

		[Parameter()]
		[Switch]$ForceChildInheritance,

		[Parameter()]
		[Switch]$EnableChildInheritance,

		[Parameter(ParameterSetName = "Reset")]
		[Switch]$ResetInheritance
    )

    Begin 
	{       	
		Function Convert-FileSystemRights {
			Param(
				[Parameter(Mandatory = $true, Position = 0)]
				[System.Security.AccessControl.FileSystemRights]$Rights
			)

			Begin {
			}

			Process {
				[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights = $Rights
				[System.Int32]$Temp = $Rights

				switch ($Temp)
				{
					#268435456
					0x10000000 {
						$ExistingFileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
						break
					}
					#-1610612736
					0xA0000000 {
						$ExistingFileSystemRights = @([System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::Synchronize)
						break
					}
					#-536805376
					0xE0010000 {
						$ExistingFileSystemRights = @([System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Synchronize)
						break
					}
					default {
						$ExistingFileSystemRights = $Rights
						break
					}
				}

				Write-Output -InputObject $ExistingFileSystemRights
			}

			End {
			}
		}

		Function Get-AuthorizationRuleComparison {
			Param(
				[Parameter(Mandatory = $true, Position = 0)]
				[System.Security.AccessControl.AuthorizationRule]$Rule1,

				[Parameter(Mandatory = $true, Position = 1)]
				[System.Security.AccessControl.AuthorizationRule]$Rule2
			)

			Begin {
			}

			Process {
				$Equal = $false

				try
				{
					[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights1  = Convert-FileSystemRights -Rights $Rule1.FileSystemRights
					[System.Security.AccessControl.FileSystemRights]$ExistingFileSystemRights2  = Convert-FileSystemRights -Rights $Rule2.FileSystemRights

					if ($ExistingFileSystemRights1 -eq $ExistingFileSystemRights2 -and `
						$Rule1.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $Rule2.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -and `
						$Rule1.AccessControlType -eq $Rule2.AccessControlType -and `
						$Rule1.InheritanceFlags -eq $Rule2.InheritanceFlags -and `
						$Rule1.PropagationFlags -eq $Rule2.PropagationFlags)
					{
						$Equal = $true
					}
				}
				catch [Exception]
				{
					Write-Log -Message "Error evaluating access rule : `nExisting $($Rule1 | FL | Out-String) `nNew $($Rule2 | FL | Out-String)" -ErrorRecord $_ -Level WARNING
				}

				Write-Output -InputObject $Equal
			}

			End {
			}
		}

		Set-TokenPrivilege -Privileges SeSecurityPrivilege -Enable
	}

    Process
    {
		if ($PSCmdlet.ParameterSetName -eq "Add" -and $AccessRules.Length -eq 0 -and $AuditRules.Length -eq 0)
		{
			throw "Either a set of access rules or audit rules must be provided to add to the path."
		}

		Write-Log -Message "Setting access and audit rules on $Path" -Level VERBOSE
		Push-Location -Path $env:SystemDrive

		[System.Boolean]$IsProtectedFromInheritance = $false

		#This is ignored if IsProtectedFromInheritance is false
		[System.Boolean]$PreserveInheritedRules = $false

		try
        {
			#$Acl = Get-Acl -Path $Path
			$Item = Get-Item -Path $Path
			[System.Security.AccessControl.FileSystemSecurity]$Acl = $Item.GetAccessControl(@([System.Security.AccessControl.AccessControlSections]::Access, [System.Security.AccessControl.AccessControlSections]::Audit))

            if ($Acl -ne $null)
            {
				switch ($PSCmdlet.ParameterSetName) {
					"ReplaceAll" {

						if ($AccessRules.Length -gt 0)
						{
							Write-Log -Message "Disabling access rule inheritance on $Path" -Level VERBOSE
							$Acl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)

							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

							foreach ($Rule in $OldAcls)
							{
								try 
								{
									$Acl.RemoveAccessRule($Rule) | Out-Null
								}
								catch [Exception] 
								{
									Write-Log -Message "Error removing access rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
								}
							}
						}

						if ($AuditRules.Length -gt 0)
						{
							Write-Log -Message "Disabling audit rule inheritance on $Path" -Level VERBOSE
							$Acl.SetAuditRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)

							Write-Log -Message "Getting audit rules" -Level VERBOSE
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							foreach ($Rule in $OldAuditRules)
							{
								try
								{
									$Acl.RemoveAuditRule($Rule) | Out-Null
								}
								catch [Exception]
								{
									Write-Log -Message "Error removing audit rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
								}
							}
						}

						break
					}
					"ReplaceNonInherited" {

						if ($AccessRules.Length -gt 0)
						{
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

							foreach ($Rule in ($OldAcls | Where-Object {$_.IsInherited -eq $false}))
							{
								try 
								{
									$Acl.RemoveAccessRule($Rule) | Out-Null
								}
								catch [Exception] 
								{
									Write-Log -Message "Error removing access rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
								}
							}
						}

						if ($AuditRules.Length -gt 0)
						{
							Write-Log -Message "Disabling audit rule inheritance on $Path" -Level VERBOSE

							Write-Log -Message "Getting non inherited audit rules" -Level VERBOSE
							[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							foreach ($Rule in $OldAuditRules)
							{
								try
								{
									$Acl.RemoveAuditRule($Rule) | Out-Null
								}
								catch [Exception]
								{
									Write-Log -Message "Error removing audit rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
								}
							}
						}

						break
					}
					"Replace" {
						
						[System.Security.Principal.SecurityIdentifier[]]$Identities = $AccessRules | Select-Object -Property @{Name = "ID"; Expression = { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } } | Select-Object -ExpandProperty ID
						foreach ($Sid in $Identities)
						{
							$Acl.PurgeAccessRules($Sid)
							$Acl.PurgeAuditRules($Sid)
						}
						
						break
					}
					"Add" {
						#Do Nothing
						break
					}
					"Reset" {
						[System.Security.AccessControl.AuthorizationRuleCollection]$OldAcls = $Acl.Access

						foreach ($Rule in $OldAcls)
						{
							$Acl.RemoveAccessRule($Rule) | Out-Null
						}
				
						$Acl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)			

						[System.Security.AccessControl.AuthorizationRuleCollection]$OldAuditRules = $Acl.GetAuditRules($script:EXPLICIT_TRUE,  $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

						foreach ($Rule in $OldAuditRules)
						{
							$Acl.RemoveAuditRule($Rule) | Out-Null
						}

						$Acl.SetAuditRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
						
						#Call set ACL since no additional rules are provided
						$Item.SetAccessControl($Acl)
					}
					"AddIfNotPresent" {
						if ($AccessRules.Length -gt 0)
						{
							foreach ($Rule in $AccessRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.Access)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule
									if ($Found -eq $true)
									{
										Write-Log -Message "Found matching access rule, no need to add this one" -Level VERBOSE
										break
									}
								}

								if ($Found -eq $false)
								{
									try
									{
										$Acl.AddAccessRule($Rule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error adding access rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}	

						if ($AuditRules.Length -gt 0)
						{
							foreach ($Rule in $AuditRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount]))
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								if ($Found -eq $false)
								{
									try
									{
										$Acl.AddAuditRule($Rule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error adding audit rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}
							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}
						break
					}
					"AddIfNotPresentAndReplace" {
						if ($AccessRules.Length -gt 0)
						{
							foreach ($ExistingRule in ($Acl.Access | Where-Object {$_.IsInherited -eq $false }))
							{
								[System.Boolean]$Found = $false

								foreach ($Rule in $AccessRules)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									#The existing rule did match a new rule
									if ($Found -eq $true)
									{
										break
									}
								}

								#The existing rule did not match a new rule, remove it
								if ($Found -eq $false)
								{
									try
									{
										Write-Log -Message "Removing rule $($Rule | FL | Out-String)" -Level VERBOSE
										$Acl.RemoveAccessRule($ExistingRule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error removing access rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}


							foreach ($Rule in $AccessRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in $Acl.Access)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								#Did not find a matching, existing rule
								if ($Found -eq $false)
								{
									try
									{
										Write-Log -Message "Adding rule $($Rule | FL | Out-String)" -Level VERBOSE
										$Acl.AddAccessRule($Rule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error adding access rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING 
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}	

						if ($AuditRules.Length -gt 0)
						{
							foreach ($ExistingRule in $Acl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount]))
							{
								[System.Boolean]$Found = $false

								foreach ($Rule in $AccessRules)
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									#The existing rule did match a new rule
									if ($Found -eq $true)
									{
										break
									}
								}

								#The existing rule did not match a new rule, remove it
								if ($Found -eq $false)
								{
									try
									{
										Write-Log -Message "Removing rule $($Rule | FL | Out-String)" -Level VERBOSE
										$Acl.RemoveAuditRule($ExistingRule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error removing audit rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING 
									}
								}
							}

							foreach ($Rule in $AuditRules)
							{
								[System.Boolean]$Found = $false

								foreach ($ExistingRule in ($Acl.GetAuditRules($script:EXPLICIT_TRUE, $true, [System.Security.Principal.NTAccount]) | Where-Object {$_.IsInherited -eq $false }))
								{
									$Found = Get-AuthorizationRuleComparison -Rule1 $ExistingRule -Rule2 $Rule

									if ($Found -eq $true)
									{
										break
									}
								}

								#Did not find a matching, existing rule
								if ($Found -eq $false)
								{
									try
									{
										Write-Log -Message "Adding audit rule $($Rule | FL | Out-String)" -Level VERBOSE
										$Acl.AddAuditRule($Rule)
									}
									catch [Exception]
									{
										Write-Log -Message "Error adding audit rule : $($Rule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}

							#Call set access control since we've already added the rules
							$Item.SetAccessControl($Acl)
						}

						break
					}
					default {
						throw "Could not determine parameter set name"
					}
				}
				
				if ($PSCmdlet.ParameterSetName -like "Replace*" -or $PSCmdlet.ParameterSetName -eq "Add")
				{
					#Add new access rules
					if($AccessRules.Length -gt 0)
					{
						foreach ($Rule in $AccessRules) 
						{
							$Acl.AddAccessRule($Rule)
						}

						$Item.SetAccessControl($Acl)
					}

					#Add new audit rules
					if ($AuditRules.Length -gt 0)
					{
						foreach ($Rule in $AuditRules)
						{
							$Acl.AddAuditRule($Rule)
						}

						$Item.SetAccessControl($Acl)
					}	
				}

				#If child permissions should be forced to inherit
				if (($ForceChildInheritance -or $EnableChildInheritance) -and [System.IO.Directory]::Exists($Path))
				{
					Write-Log -Message "Evaluating child items" -Level VERBOSE
					Get-ChildItem -Path $Path -Recurse -Force | ForEach-Object {

						$ChildItem = Get-Item -Path $_.FullName
						[System.Security.AccessControl.FileSystemSecurity]$ChildAcl = $ChildItem.GetAccessControl(@([System.Security.AccessControl.AccessControlSections]::Access, [System.Security.AccessControl.AccessControlSections]::Audit))

						if ($AccessRules.Length -gt 0 -or $PSCmdlet.ParameterSetName -eq "Reset")
						{
							if ($ForceChildInheritance)
							{
								Write-Log -Message "Forcing access rule inheritance on $($ChildItem.FullName)" -Level VERBOSE

								foreach ($ChildRule in ($ChildAcl.Access | Where-Object {$_.IsInherited -eq $false }))
								{
									try
									{
										$ChildAcl.RemoveAccessRule($ChildRule) | Out-Null
									}
									catch [Exception]
									{
										Write-Log -Message "Error removing ACL from $($ChildItem.FullName)`: $($ChildRule | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}

							try
							{
								$ChildAcl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
								$ChildItem.SetAccessControl($ChildAcl)
							}
							catch [Exception]
							{
								Write-Log -Message "Could not set ACL on path $ChildPath." -ErrorRecord $_ -Level WARNING
							}
						}

						if ($AuditRules.Length -gt 0 -or $PSCmdlet.ParameterSetName -eq "Reset")
						{
							Write-Log -Message "Forcing audit rule inheritance on $($ChildItem.FullName)" -Level VERBOSE

							[System.Security.AccessControl.AuthorizationRuleCollection]$OldChildAuditRules = $ChildAcl.GetAuditRules($script:EXPLICIT_TRUE, $script:INHERITED_FALSE, [System.Security.Principal.NTAccount])

							if ($ForceChildInheritance)
							{
								foreach ($ChildAudit in $OldChildAuditRules)
								{
									try
									{
										$ChildAcl.RemoveAuditRule($ChildAudit) | Out-Null
									}
									catch [Exception]
									{
										Write-Log -Message "Error removing audit from $($ChildItem.FullName)`: $($ChildAudit | FL | Out-String)" -ErrorRecord $_ -Level WARNING
									}
								}
							}

							try
							{
								$ChildAcl.SetAccessRuleProtection($IsProtectedFromInheritance, $PreserveInheritedRules)
								$ChildItem.SetAccessControl($ChildAcl)
							}
							catch [Exception]
							{
								Write-Log -Message "Could not set ACL on path $ChildPath." -ErrorRecord $_ -Level WARNING
							}
						}
					}
				}                   
            }
            else
            {
                Write-Log -Message "Could not retrieve the ACL for $Path." -Level WARNING
            }
        }
        catch [System.Exception]
        {
            Write-Log -ErrorRecord $_ -Level WARNING
        }

		Pop-Location
    }
    
    End {
	}
}

Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'Builtin\Administrators'

        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder. If the specified path is a file, this parameter is ignored.

		.EXAMPLE
            PS C:\>Set-Owner -Path C:\temp\test.txt

            Changes the owner of test.txt to Builtin\Administrators

        .EXAMPLE
            PS C:\>Set-Owner -Path C:\temp\test.txt -Account Domain\user

            Changes the owner of test.txt to Domain\user

        .EXAMPLE
            PS C:\>Set-Owner -Path C:\temp -Recurse 

            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators

        .EXAMPLE
            PS C:\>Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\Administrator'

            Changes the owner of all files and folders under C:\Temp to Domain\Administrator

		.INPUTS
			None

		.OUTPUTS
			None

        .NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/23/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [Alias("FullName")]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Path,

        [Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
        [System.String]$Account = 'BUILTIN\Administrators',

        [Parameter()]
        [Switch]$Recurse,

        [Parameter()]
        [Switch]$Force
    )

    Begin {
        if (-not (Test-IsLocalAdmin)) {
			throw "Run the cmdlet with elevated credentials."
		}

        Set-TokenPrivilege -Privileges @("SeRestorePrivilege","SeBackupPrivilege","SeTakeOwnershipPrivilege") -Enable
    }

    Process {
        Write-Log -Message "Set Owner Path: $Path" -Level VERBOSE
		$Account = Get-AccountTranslatedNTName -UserName $Account
		Write-Log -Message "Account Name: $Account" -Level VERBOSE

        #The ACL objects do not like being used more than once, so re-create them on the Process block
        $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
        $DirOwner.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount($Account)))
        
		$FileOwner = New-Object System.Security.AccessControl.FileSecurity
        $FileOwner.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount($Account)))
        
        try {
			$Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

            if (-not $Item.PSIsContainer) 
            {
                $ConfirmMessage = "You are about to change the owner of $($Item.FullName) to $Account."
				$WhatIfDescription = "Set Owner of $($Item.FullName)."
				$ConfirmCaption = "Set File Owner"

				if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
				{
                    $Item.SetAccessControl($FileOwner)
                    Write-Log -Message "Set ownership to $Account on $($Item.FullName)" -Level VERBOSE
                }
            }
            else
            {
                $ConfirmMessage = "You are about to change the owner of $($Item.FullName) to $Account."
				$WhatIfDescription = "Set Owner of $($Item.FullName)."
				$ConfirmCaption = "Set Directory Owner"

				if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
				{
                    $Item.SetAccessControl($DirOwner)
                    Write-Log -Message "Set ownership to $Account on $($Item.FullName)" -Level VERBOSE
                }

                if ($Recurse) 
				{
					Get-ChildItem $Item -Force -Recurse | ForEach-Object {
						Set-Owner -Path $_.FullName -Account $Account -Force
					}
				}
            }
        }
        catch [Exception] {
            Write-Log -Message "Failed to set owner on $($Item.FullName)" -ErrorRecord $_ -Level WARNING
        }
    }

    End {
        Set-TokenPrivilege -Privileges @("SeRestorePrivilege","SeBackupPrivilege","SeTakeOwnershipPrivilege") -Disable
    }
}

Function Invoke-ForceDelete {
	<#
		.SYNOPSIS
			The cmdlet forces the deletion of a file or folder and all of its content.

		.DESCRIPTION
			The cmdlet takes ownership of the file or content in a directory and grants the current user
			full control permissions to the item. Then it deletes the item and performs this recursively
			through the directory structure specified.
		
		.PARAMETER Path
			The path to the file or folder to forcefully delete.

		.PARAMETER Force
			Ignores the confirmation to delete each item.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Invoke-ForceDelete -Path c:\windows.old

			Forcefully deletes the c:\windows.old directory and all of its content.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 4/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ 
            try {
               Test-Path -Path $_ -ErrorAction Stop
            }
            catch [System.UnauthorizedAccessException] {
                $true
            } 
        })]
		[System.String]$Path,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {	
		# Fix any paths that were fed in dot sourced
		$Path = Resolve-Path -Path $Path
		$IsDir = [System.IO.Directory]::Exists($Path)

        Write-Log -Message "Invoke-ForceDelete cmdlet called with path $Path." -Level VERBOSE

		[System.String]$UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
		$UserName = Get-AccountTranslatedNTName -UserName $UserName

        # Take ownership of the provided path
        Set-Owner -Path $Path -Account $UserName -Recurse -Force

		# Full Control to "This folder, subfolders, and files"
		[System.Security.Principal.NTAccount]$NTAccount = New-Object -TypeName System.Security.Principal.NTAccount($UserName)
        [System.Security.Principal.SecurityIdentifier]$Sid = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
		
		if ($IsDir)
		{
			$Ace = New-Object System.Security.AccessControl.FileSystemAccessRule($Sid,
				[System.Security.AccessControl.FileSystemRights]::FullControl,
				([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
				[System.Security.AccessControl.PropagationFlags]::None,
				[System.Security.AccessControl.AccessControlType]::Allow       
			)
		}
		else
		{
			$Ace = New-Object System.Security.AccessControl.FileSystemAccessRule($Sid,
				[System.Security.AccessControl.FileSystemRights]::FullControl,
				[System.Security.AccessControl.InheritanceFlags]::None,
				[System.Security.AccessControl.PropagationFlags]::None,
				[System.Security.AccessControl.AccessControlType]::Allow       
			)
		}

		Set-FileSecurity -Path $Path -AccessRules $Ace -ForceChildInheritance

		# If it's a directory, remove all of the child content
		if ($IsDir)
		{
            Write-Log -Message "The current path $Path is a directory." -Level VERBOSE

			Get-ChildItem -Path $Path -Force | ForEach-Object { 		
                Invoke-ForceDelete -Path $_.FullName -Force
			}
		}
        
        # Remove the specified path whether it is a folder or file
		try
        {	
			$ConfirmMessage = "You are about to force delete $Path."
			$WhatIfDescription = "Deleted $Path."
			$ConfirmCaption = "Force Delete"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Log -Message "Deleting $Path" -Level VERBOSE
				Remove-Item -Path $Path -Confirm:$false -Force -Recurse

				$Counter = 0

				do 
				{
					try {
						$Found = Test-Path -Path $Path -ErrorAction Stop
					}
					catch [System.UnauthorizedAccessException] {
						$Found = $true
					}

					Start-Sleep -Milliseconds 100
                
				} while (($Found -eq $true) -and $Counter++ -lt 50)

				if ($Counter -eq 50)
				{
					Write-Log -Message "Timeout waiting for $Path to delete" -Level WARNING
				}
			}
        }
        catch [Exception]
        {
            Write-Log -ErrorRecord $_ -Level WARNING
        }      
	}

	End {
	}
}

Function Rename-FileOrDirectory {
	<#
		.SYNOPSIS
			The cmdlet renames a file or directory and uses an incrementing counter appended to the desired filename if it already exists.

		.DESCRIPTION
			The cmdlet attempts to rename a file with the specified new name. If the new name already exists, the postfix "(#)" is added before the file extension, 
			or the end of the directory name, where "#" is a number starting from 1 and incrementing by 1 until the new name is unique in the directory.

		.PARAMETER Path
			The file or directory to rename.

		.PARAMETER NewName
			The new name of the file or directory. Use a literal, not relative, path.

		.PARAMETER Credential
			The credential to use to perform the operation.

		.EXAMPLE
			Rename-FileOrDirectory -Path c:\temp\file1.txt -NewName c:\temp\file2.txt -PassThru

			In this example the file c:\temp\file2.txt and c:\temp\file2(1).txt already exists. The file c:\temp\file1.txt is renamed to
			c:\temp\file2(2).txt and the file info about its resulting name is returned to the pipeline.

		.INPUTS
			System.String

		.OUTPUTS
			None or System.IO.DirectoryInfo or System.IO.FileInfo

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/23/2017
	#>
	[CmdletBinding()]
	[OutputType([System.IO.FileInfo], [System.IO.DirectoryInfo])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path,

		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$NewName,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter()]
		[Switch]$PassThru
	)

	Begin{
	}

	Process {
		[System.IO.FileInfo]$Info = New-Object -TypeName System.IO.FileInfo($Path)
		$Base = $Info.DirectoryName
		$Name = $Info.BaseName
		$Ext = $Info.Extension

		$Counter = 1

		while (Test-Path -Path $NewName)
		{
			$NewName = "$Base\$Name($Counter)$Ext"
			$Counter++
		}

		[System.Collections.Hashtable]$Splat = @{}

		if ($Force)
		{
			$Splat.Add("Force", $true)
		}

		if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
		{
			$Splat.Add("Credential", $Credential)
		}

		if ($PassThru)
		{
			$Splat.Add("PassThru", $true)
		}

		Rename-Item -Path $Path -NewName $NewName @Splat
	}

	End {
	}
}

Function Get-FileVersion {
	<#
		.SYNOPSIS
			Gets the version of a specific file or file running a Windows service from its metadata.

		.DESCRIPTION
			This cmdlet gets the FileVersion data from a specified file or file running a service. If no version is included in the FileInfo, the cmdlet returns "0".

		.PARAMETER Path
			The path to the file.

		.PARAMETER Service
			The name of the service.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-FileVersion -Path "c:\installer.exe"

			Gets the file version of installer.exe.

		.EXAMPLE
			Get-FileVersion -Service lmhosts

			Gets the file version of the svchost.exe running the lmhosts service.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "File", ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Path
	)

	DynamicParam
    {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$Services = Get-Service | Select-Object -ExpandProperty Name
		New-DynamicParameter -Name "ServiceName" -ParameterSets "Service" -Type ([System.String]) -Mandatory -ValueFromPipeline -Position 0 -ValidateSet $Services -RuntimeParameterDictionary $ParamDictionary | Out-Null

		return $ParamDictionary
	}

	Begin {
	}

	Process {
		switch ($PSCmdlet.ParameterSetName) {
			"File" {
				break
			}
			"Service" {
				$Path = (Get-WmiObject -Class Win32_Service -Filter "Name = `"$($PSBoundParameters.ServiceName)`"" | Select-Object -ExpandProperty PathName).Trim("`"")
				break
			}
			default {
				Write-Log -Message "Could not determine parameter set name from given parameters." -Level FATAL
			}
		}

		$Version = New-Object -TypeName System.IO.FileInfo($Path) | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion

		if ([System.String]::IsNullOrEmpty($Version))
		{
			$Version = "0"
		}

		Write-Output -InputObject $Version
	}

	End {	
	}
}

Function Invoke-ExtractZip {
	<#
		.SYNOPSIS
			The cmdlet extracts the contents of a zip file to a specified destination.

		.DESCRIPTION
			The cmdlet extracts the contents of a zip file to a specified destination and optionally preserves the contents in the destination if they already exist.

		.PARAMETER Source
			The path to the zip file.

		.PARAMETER Destination
			The folder where the zip file should be extracted. The destination is created if it does not already exist.

		.PARAMETER NoOverwrite
			Specify if the contents in the destination should be preserved if they already exist.

		.PARAMETER OverwriteIfNewer
			Only overwrite existing files if the file in the zip is newer (by last modification date) than the existing file.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE 
			Invoke-ExtractZip -Source "c:\test.zip" -Destination "c:\test"

			Extracts the contents of test.zip to c:\test.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/27/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "Overwrite")]
	[OutputType()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Source,

		[Parameter(Position = 1, Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Destination,

		[Parameter(ParameterSetName = "No")]
		[Switch]$NoOverwrite,

		[Parameter(ParameterSetName = "Newer")]
		[Switch]$OverwriteIfNewer
	)

	Begin {
		Add-Type -AssemblyName System.IO.Compression.FileSystem
	}

	Process {
		if (!(Test-Path -Path $Source)) {
			throw (New-Object -TypeName System.IO.FileNotFoundException("Source zip file not found."))
		}

		if (-not (Test-Path -Path $Destination)) {

			Write-Log -Message "Zip extract destination $Destination does not exist, creating it."

			try {
				New-Item -Path $Destination -ItemType Directory | Out-Null

				$Counter = 0

				while (!(Test-Path -Path $Destination)) {
					Start-Sleep -Seconds 1
					$Counter++

					if ($Counter -gt 60) {
						throw "Timeout error waiting for the zip extraction destination $Destination to be created."
					}
				}
			}
			catch [Exception] {
				Write-Log -ErrorRecord $_ -Level FATAL
			}
		}
		else {
			if ([System.IO.File]::Exists($Destination)) {
				throw (New-Object -TypeName System.IO.DirectoryNotFoundException("The destination is a file, not a directory."))
			}
		}

		[System.IO.Compression.ZipArchive]$ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($Source)
			
		try
		{
			foreach ($ZipArchiveEntry in $ZipArchive.Entries) 
			{
				$FullPath = [System.IO.Path]::Combine($Destination, $ZipArchiveEntry.FullName)
				[System.String]$Directory = [System.IO.Path]::GetDirectoryName($FullPath)
				
				if (-not [System.IO.Directory]::Exists($Directory))
				{
					[System.IO.Directory]::CreateDirectory($Directory)
				}

				Write-Log -Message "Evaluating $($ZipArchiveEntry.FullName) to unzip to $FullPath." -Level VERBOSE

				# If we don't want to overwrite existing files, check to see if the path exists
				if ($NoOverwrite)
				{
					# If it doesn't exist, we'll extract
					if (-not (Test-Path -Path $FullPath))
					{
						# To handle the race condition of extracting it and the file could have been created before the extraction occurs
						# catch the IOException and check to see if it's because the file already exists, if it is, ignore the exception, otherwise,
						# throw the exception
						try
						{
							[System.IO.Compression.ZipFileExtensions]::ExtractToFile($ZipArchiveEntry, $FullPath)
						}
						catch [System.IO.IOException]
						{
							if ($_.Exception.Message -inotlike "*already exists.")
							{
								throw $_.Exception
							}
						}
					}
				}
				else
				{
					# If we are overwriting files, but only want to overwrite if the zip file is newer, check to see if it exists
					if ($OverwriteIfNewer)
					{
						# If the file exists, check the last modified times
						if (Test-Path -Path $FullPath)
						{
							if ((New-Object -TypeName System.IO.FileInfo($FullPath)).LastWriteTimeUtc -lt $ZipArchiveEntry.LastWriteTime.ToUniversalTime().Date)
							{
								Write-Log -Message "Overwriting zip output $FullPath with newer file." -Level VERBOSE
								[System.IO.Compression.ZipFileExtensions]::ExtractToFile($ZipArchiveEntry, $FullPath, $true)
							}
						}
						else
						{
							[System.IO.Compression.ZipFileExtensions]::ExtractToFile($ZipArchiveEntry, $FullPath, $true)
						}
					}
					else
					{
						[System.IO.Compression.ZipFileExtensions]::ExtractToFile($ZipArchiveEntry, $FullPath, $true)
					}
				}
			}
		}
		catch [Exception]
		{
			Write-Log -ErrorRecord $_ -Level FATAL
		}
		finally
		{
			$ZipArchive.Dispose()
		}
	}

	End {		
	}
}

Function Invoke-ExtractGZip {
	<#
		.SYNOPSIS
			The cmdlet extracts the contents of a gzip file to a specified destination.

		.DESCRIPTION
			The cmdlet first examines the gzip file to see if it contains concatenated files. If it does, it separates those chunks and decompresses each chunk to its
			own file, or if specified, to the same file. If the contents are each written to their own file, each file is written to the destination directory using
			a "(#)" post fix for each file after the first. The decompressed files will not use an extension, or can optionally use an extension you specify

		.PARAMETER Source
			The path to the gzip file.

		.PARAMETER Destination
			The folder where the gzip file should be extracted. The destination is created if it does not already exist.

		.PARAMETER CreateSingleFile
			Creates a single file in case the gzip contains concatenated gzip files. If this is not specified and the gzip contains concatenated files, each
			concatenated file it written to its own output file.

		.PARAMETER NoOverwrite
			Specify this to not overwrite an existing file in the destination directory.

		.PARAMETER Extension
			The extension to use on the decompressed files. If this is not specified, any extension contained in the filename is used. For example, if the
			input source is file.json.gz, the extension on the output is .json since the .gz is stripped off. If you provided "txt" as the extension, the output
			file would be file.json.txt.

		.INPUTS
			System.String
		
		.OUTPUTS
			None or System.IO.FileInfo[]

		.EXAMPLE 
			Invoke-ExtractGZip -Source "c:\test.gz" -Destination "c:\test" -Extension "txt"

			Extracts the contents of test.gzip to c:\test\test.txt

		.EXAMPLE 
			Invoke-ExtractGZip -Source "c:\test.json.gz" -Destination "c:\test"

			In this example, the gzip contains 2 concatenated files. The output is:

			c:\test\test.json
			c:\test\test(1).json

		.EXAMPLE
			Invoke-ExtractGZip -Source "c:\test.json.gz" -Destination "c:\test" -CreateSingleFile

			In this example, the gzip contains 2 concatenated files, but the contents of both files are output to a single file, c:\test\test.json.
		
			As a note, the resulting json file would not be well-formatted since it contains to JSON objects not inside an array.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/27/2017
	#>
	[CmdletBinding()]
	[OutputType([System.IO.FileInfo[]])]
	Param(
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Source,

		[Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Destination,

		[Parameter()]
		[Switch]$NoOverwrite,

		[Parameter()]
		[Switch]$CreateSingleFile,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Extension,

		[Parameter()]
		[Switch]$PassThru
	)

	Begin {
		Add-Type -AssemblyName System.IO.Compression.FileSystem
	}

	Process {
		[System.Byte[]]$FileBytes = [System.IO.File]::ReadAllBytes($Source)
		[System.Int32[]]$StartIndexes = @()
		
        # This pattern indicates the start of a GZip file as found from looking at the files
        # The file header is 10 bytes in size
        # 0-1  Signature 0x1F, 0x8B
        # 2    Compression Method - 0x08 is for DEFLATE, 0-7 are reserved
        # 3    Flags
        # 4-7  Last Modification Time
        # 8    Compression Flags
        # 9    Operating System
        
		[System.Byte[]]$StartOfFilePattern = [System.Byte[]](0x1F, 0x8B, 0x08)

		# This will limit the last byte we check to make sure it doesn't exceed the end of the file
        # If the file is 100 bytes and the file pattern is 10 bytes, the last byte we want to check is 
        # 90 -> i.e. we will check index 90, 91, 92, 93, 94, 95, 96, 97, 98, 99 and index 99 is the last
        # index in the file bytes
		[System.Int64]$TraversableLength = $FileBytes.LongLength - $StartOfFilePattern.LongLength

		for ($i = 0; $i -le $TraversableLength; $i++)
		{
			[System.Boolean]$Match = $true

			# Test the next run of characters to see if they match
			for ($j = 0; $j -lt $StartOfFilePattern.Length; $j++)
			{
				# If the character doesn't match, break out
                # We're making sure that i + j doesn't exceed the length as part
                # of the loop bounds
				if ($FileBytes[$i + $j] -ne $StartOfFilePattern[$j])
				{
					$Match = $false
					break
				}
			}

            # If we did find a run of matching bytes 
			if ($Match -eq $true)
			{
				$StartIndexes += $i
				# Since we had a match, move the index ahead the length of the start of file pattern
				# Then the for loop will add 1 to move to the next index
				$i += $StartOfFilePattern.Length
			}
        }

		# In case the pattern doesn't match, just start from the beginning of the file
        if ($StartIndexes.Count -eq 0)
        {
            $StartIndexes += 0
        }

		[System.Collections.Generic.List[System.Byte[]]]$Chunks = New-Object -TypeName System.Collections.Generic.List[System.Byte[]]

		for ($i = 0; $i -lt $StartIndexes.Count; $i++)
		{
			[System.Int32]$Start = $StartIndexes[$i]

			[System.Int32]$Length = 0

			# If this index is the last index, take the rest of the file bytes
			if ($i + 1 -eq $StartIndexes.Count)
			{
				$Length = $FileBytes.Length - $Start
			}
			# Otherwise take the chunk from this start to the next one
			else
			{
				# The length to read is the next start index minus the current start index
				$Length = $StartIndexes[$i + 1] - $StartIndexes[$i]
			}

			if ($Length -gt 0)
			{
				$Chunks.Add(($FileBytes | Select-Object -Skip $Start -First $Length))
			}
		}

		[System.IO.MemoryStream]$MStreamOut = New-Object -TypeName System.IO.MemoryStream
		[System.IO.FileInfo]$Info = New-Object -TypeName System.IO.FileInfo($Source)
		[System.Int32]$Counter = 0

        if (-not [System.String]::IsNullOrEmpty($Extension))
        {
            if ($Extension.StartsWith("."))
            {
                $Extension = $Extension.Substring(1)
            }
        }

        if (-not $CreateSingleFile)
        {
            [System.String]$BaseName = $Info.BaseName

            if ([System.String]::IsNullOrEmpty($Extension))
            {
                if ($BaseName.Contains("."))
                {
                    $Extension = $BaseName.Substring($BaseName.IndexOf(".") + 1)
                    $BaseName = $BaseName.Substring(0, $BaseName.IndexOf("."))
                }
            }
        }
        
		[System.IO.FileInfo[]]$Results = @()

		try
		{
			foreach ($Chunk in $Chunks)
			{
				[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream(,$Chunk)

				try
				{
					[System.IO.Compression.GZipStream]$GZStream = New-Object -TypeName System.IO.Compression.GZipStream($MStream, [System.IO.Compression.CompressionMode]::Decompress)
				
					try
					{
						$GZStream.CopyTo($MStreamOut)

						if (-not $CreateSingleFile)
						{		
							[System.String]$FileName = [System.IO.Path]::Combine($Destination, "$BaseName$(if ($Counter -gt 0) {"($Counter)"})$(if (-not [System.String]::IsNullOrEmpty($Extension)) { ".$Extension" })")							
                            $Counter++

							[System.IO.File]::WriteAllBytes($FileName, $MStreamOut.ToArray())
							$Results += (Get-Item -Path $FileName)

							# Reset the output memory stream
							$MStreamOut.SetLength(0)
						}
					}
					finally
					{
						$GZStream.Dispose()
					}
				}
				finally
				{
					$MStream.Dispose()
				}
			}
				
			if ($CreateSingleFile)
			{
				$FileName = [System.IO.Path]::Combine($Destination, "$($Info.BaseName)$(if (-not [System.String]::IsNullOrEmpty($Extension)) {".$Extension"})")
				[System.IO.File]::WriteAllBytes($FileName, $MStreamOut.ToArray())
				$Results += (Get-Item -Path $FileName)
			}
		}
		finally
		{
			$MStreamOut.Dispose()
		}

		if ($PassThru)
		{
			Write-Output -InputObject $Results
		}
	}

	End {
	}
}

Function New-ISO {
    <#
        .SYNOPSIS
            Creates a new ISO image from the specified content.

        .DESCRIPTION
            This cmdlet creates in ISO image file containing specified content. It can also be used to make a bootable ISO with something like WinPE.

        .PARAMETER Content
            The FileInfo, DirectoryInfo, or string Path names of the files and folders to include in the ISO. Each item will be added to the root of the ISO file system tree.

        .PARAMETER Destination
            The location the ISO file will be created and written to. Use -Force to overwrite an existing file.

        .PARAMETER BootFile
            The path to a boot file. For example c:\Program Files (X86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin".

        .PARAMETER Media
            The media type to emulate with the ISO. This defaults to DVDPLUSRW_DUALLAYER.

        .PARAMETER Title
            The title of the ISO image file.

        .EXAMPLE
            New-ISO -Content c:\users\john.smith\Desktop -Destination c:\users\john.smith\desktop\backup.iso

            This creates a new ISO image file on the user's desktop containing the desktop folder at the root of the ISO with all of its contents inside.

        .EXAMPLE
            Get-ChildItem -Path c:\users\john.smith\Desktop | New-ISO -Destination c:\users\john.smith\desktop\backup.iso

            This creates a new ISO image file on the user's desktop containing the contents of the desktop folder at the root of the ISO.

        .EXAMPLE
            Get-ChildItem -Path c:\WinPE | New-ISO -Destination c:\temp\WinPE.iso -BootFile "$env:ProgramFiles(x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE" 

            This creates a bootable ISO from WinPE and includes the contents of the c:\WinPE folder in the image.

        .INPUT
            System.Object[]

        .OUTPUT
            System.IO.FileInfo

        .NOTES
            AUTHOR: Michael Haken
            LAST UPDATE: 2/23/2019
    #>

    [CmdletBinding(DefaultParameterSetName = "Content")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Content", ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]$Content,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Destination,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Path -Path $_
        })]
        [System.String]$BootFile = [System.String]::Empty,

        [Parameter()]
        [ValidateSet("CDR","CDRW","DVDRAM","DVDPLUSR","DVDPLUSRW","DVDPLUSR_DUALLAYER","DVDDASHR","DVDDASHRW","DVDDASHR_DUALLAYER","DISK","DVDPLUSRW_DUALLAYER","BDR","BDRE")]
        [System.String]$Media = "DVDPLUSRW_DUALLAYER",

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Title = ([System.DateTime]::UtcNow.ToString("yyyy-mm-ddThh:mm:ss.fff")),

        [Parameter()]
        [Switch]$Force
    )

    Begin {
        if (-not [System.String]::IsNullOrEmpty($BootFile)) 
        {       
            if (@("BDR","BDRE") -contains $Media) 
            { 
                throw "Bootable image doesn't work with media type $Media." 
            } 

            $BootFileName = Get-Item -LiteralPath $BootFile | Select-Object -ExpandProperty FullName
            $Stream = New-Object -ComObject ADODB.Stream -Property @{Type = 1}
            $Stream.Open()
            $Stream.LoadFromFile($BootFileName)
            $BootOptions = New-Object -ComObject IMAPI2FS.BootOptions
            $BootOptions.AssignBootImage($Stream)
        }
        
        if (([System.AppDomain]::CurrentDomain.GetAssemblies() | 
            Where-Object { -not [System.String]::IsNullOrEmpty($_.Location) } | 
            Select-Object -Property @{Name = "Type"; Expression = {$_.GetTypes()}} |
            Select-Object -ExpandProperty Type |
            Where-Object { $_.FullName -eq "BAMCIS.FileIO.ISO.IMAPI_MEDIA_PHYSICAL_TYPE" }).Count -eq 0)
        {
            # The members are prefaced with IMAPI_MEDIA_TYPE_ in the real enum
            Add-Type -TypeDefinition @"
namespace BAMCIS.FileIO.ISO
{
    public enum IMAPI_MEDIA_PHYSICAL_TYPE
    {
        UNKNOWN,
        CDROM,
        CDR,
        CDRW,
        DVDROM,
        DVDRAM,
        DVDPLUSR,
        DVDPLUSRW,
        DVDPLUSR_DUALLAYER,
        DVDDASHR,
        DVDDASHRW,
        DVDDASHR_DUALLAYER,
        DISK,
        DVDPLUSRW_DUALLAYER,
        HDDVDROM,
        HDDVDR,
        HDDVDRAM,
        BDROM,
        BDR,
        BDRE,
        MAX
    }
}
"@
        }

        
        if (([System.AppDomain]::CurrentDomain.GetAssemblies() | 
            Where-Object { -not [System.String]::IsNullOrEmpty($_.Location) } | 
            Select-Object -Property @{Name = "Type"; Expression = {$_.GetTypes()}} |
            Select-Object -ExpandProperty Type |
            Where-Object { $_.FullName -eq "BAMCIS.FileIO.ISO.ISOFile" }).Count -eq 0)
        {
            [System.CodeDom.Compiler.CompilerParameters]$CompilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
            $CompilerParameters.CompilerOptions = "/unsafe"

            # Needs to be unsafe so that we can reference
            Add-Type -CompilerParameters $CompilerParameters -TypeDefinition @"
using System.Runtime.InteropServices.ComTypes;
using System.IO;
using System;

namespace BAMCIS.FileIO.ISO
{
    public class ISOFile
    {
        private ISOFile()
        {
        }

        public unsafe static void Create(string path, object stream, int blockSize, int totalBlocks)
        {
            int Bytes = 0;
            IntPtr SeekPointer = (IntPtr)(&Bytes);
            byte[] Buffer = new byte[blockSize];
            IStream InputStream = stream as IStream;

            using (FileStream FStream = System.IO.File.OpenWrite(path))
            {          
                if (FStream != null)
                {
                    while (totalBlocks > 0)
                    {
                        InputStream.Read(Buffer, blockSize, SeekPointer);
                        FStream.Write(Buffer, 0, Bytes);
                        totalBlocks += -1;
                    }
                }
                else
                {
                    throw new InvalidOperationException(String.Format("The file stream at {0} was null.", path));
                }
            }
        }
    }
}
"@
        }

        [BAMCIS.FileIO.ISO.IMAPI_MEDIA_PHYSICAL_TYPE]$MediaType = [System.Enum]::Parse([BAMCIS.FileIO.ISO.IMAPI_MEDIA_PHYSICAL_TYPE], $Media)
       
        Write-Verbose -Message "Selected media type is $($MediaType.ToString()) with value $([System.Int32]$MediaType)."

        $Image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{VolumeName = $Title}
        $Image.ChooseImageDefaultsForMediaType(([Int32]$MediaType)) 
    }

    Process {
        foreach ($Item in $Content)
        {
            if ($Item -isnot [System.IO.FileInfo] -and $Item -isnot [System.IO.DirectoryInfo])
            {
                $Item = Get-Item -LiteralPath $Item
            }

            Write-Verbose -Message "Adding $($Item.FullName) to image."

            try 
            { 
                $Image.Root.AddTree($Item.FullName, $true) 
            } 
            catch [Exception] 
            { 
                throw "$($_.Exception.Message) : Try a different media type." 
            } 
        }
    }

    End {
        if ($BootOptions -ne $null) 
        { 
            $Image.BootImageOptions = $BootOptions 
        }  
    
        $Result = $Image.CreateResultImage()  

        if (-not ($Target = New-Item -Path $Destination -ItemType File -Force:$Force -ErrorAction SilentlyContinue))
        {
            throw "Could not create file at $Destination. Use -Force parameter to overwrite an existing file."
        }

        [BAMCIS.FileIO.ISO.ISOFile]::Create(
            $Target.FullName,
            $Result.ImageStream,
            $Result.BlockSize,
            $Result.TotalBlocks
        ) 
    
        Write-Verbose -Message "Target image $($Target.FullName) has been created"
    
        Write-Output -InputObject $Target
    }
}