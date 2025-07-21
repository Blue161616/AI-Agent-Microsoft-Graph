# PowerShell script to create an app registration with <>.Read. permissions
# View-only permissions for to prompt the Microsoft Graph API for Security
# Requires Microsoft.Graph PowerShell module

#Requires -Modules Microsoft.Graph.Applications

param(
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$InteractiveAuth = $true
)

# Function to write colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }
    
    $host.UI.RawUI.ForegroundColor = $fc
}

try {
    Write-ColorOutput Green "=== Microsoft Graph App Registration Creator ==="
    Write-Host ""
    
    # Check if Microsoft.Graph module is installed
    Write-ColorOutput Yellow "Checking Microsoft Graph PowerShell module..."
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Applications
    
    if (-not $graphModule) {
        Write-ColorOutput Red "Microsoft.Graph.Applications module not found!"
        Write-ColorOutput Yellow "Installing Microsoft Graph PowerShell module..."
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
        Write-ColorOutput Green "Microsoft Graph module installed successfully."
    } else {
        Write-ColorOutput Green "Microsoft Graph module found."
    }
    
    # Import required modules
    Import-Module Microsoft.Graph.Applications
    Import-Module Microsoft.Graph.Authentication
    
    # Connect to Microsoft Graph
    Write-ColorOutput Yellow "Connecting to Microsoft Graph..."
    
    if ($TenantId) {
        if ($InteractiveAuth) {
            Connect-MgGraph -TenantId $TenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All" -NoWelcome
        } else {
            # For non-interactive scenarios, you would use certificate or client secret authentication
            Write-ColorOutput Red "Non-interactive authentication requires additional setup (certificate or client secret)"
            exit 1
        }
    } else {
        if ($InteractiveAuth) {
            Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.Read.All" -NoWelcome
        } else {
            Write-ColorOutput Red "Non-interactive authentication requires TenantId and additional setup"
            exit 1
        }
    }
    
    Write-ColorOutput Green "Successfully connected to Microsoft Graph."
    
    # Get Microsoft Graph service principal (for API permissions)
    Write-ColorOutput Yellow "Getting Microsoft Graph service principal..."
    $graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    
    if (-not $graphServicePrincipal) {
        Write-ColorOutput Red "Failed to find Microsoft Graph service principal!"
        exit 1
    }
    
    # Define the required API permissions
Write-ColorOutput Yellow "Defining API permissions..."

    # Application.Read.All (Delegated) - ID: c79f8feb-a9db-4090-85f9-90d820caa0eb
    # AuditLog.Read.All (Delegated) - ID: e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20
    # Directory.Read.All (Delegated) - ID: 06da0dbc-49e2-44d2-8312-53f166ab848a
    # Policy.Read.All (Delegated) - ID: ba22922b-752c-446f-89d7-a2d92398fceb
    # Policy.Read.AuthenticationMethod (Delegated) - ID: a6ff13ac-1851-4993-8ca9-a671d70de2d5
    # Policy.Read.ConditionalAccess (Delegated) - ID: 633e0fce-8c58-4cfb-9495-12bbd5a24f7c
    # Policy.Read.DeviceConfiguration (Delegated) - ID: 3616a4b0-6746-49c4-a678-4c237599074d
    # Policy.Read.IdentityProtection (Delegated) - ID: d146432f-b803-4ed4-8d42-ba74193a6ede
    # Policy.Read.PermissionGrant (Delegated) - ID: 414de6ea-2d92-462f-b120-6e2a809a6d01
    # SecurityActions.Read.All (Delegated) - ID: 1638cddf-07a4-4de2-8645-69c96cacad73 
    # SecurityAlert.Read.All (Delegated) - ID: bc257fb8-46b4-4b15-8713-01e91bfbe4ea
    # SecurityAnalyzedMessage.Read.All (Delegated) - ID: 53e6783e-b127-4a35-ab3a-6a52d80a9077
    # SecurityEvents.Read.All (Delegated) - ID: 64733abd-851e-478a-bffb-e47a14b18235
    # SecurityIdentitiesAccount.Read.All (Delegated) - ID: 3e9ed69a-a48e-473c-8b97-413016703a37
    # SecurityIdentitiesHealth.Read.All (Delegated) - ID: a0d0da43-a6df-4416-b63d-99c79991aae8
    # SecurityIdentitiesSensors.Read.All (Delegated) - ID: 2c221239-7c5c-4b30-9355-d84663bfcd96
    # SecurityIdentitiesUserActions.Read.All (Delegated) - ID: c7d0a939-da1c-4aca-80fa-d0a6cd924801
    # SecurityIncident.Read.All (Delegated) - ID: b9abcc4f-94fc-4457-9141-d20ce80ec952
    # User.Read (delegated) - ID: e1fe6dd8-ba31-4d61-89e7-88639da4683d
    # User.Read.All (delegated) - ID: a154be20-db9c-4678-8ab7-66f6cc099a59
    # UserAuthenticationMethod.Read.All (Delegated) - ID: aec28ec7-4d02-4e8c-b864-50163aea77eb

    $ApplicationReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Application.Read.All" }
    $AuditLogReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "AuditLog.Read.All" }
    $PolicyReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Directory.Read.All" }
    $userReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.All" }
    $PolicyReadAuthenticationMethodPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.AuthenticationMethod" }
    $PolicyReadConditionalAccessPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.ConditionalAccess" }
    $PolicyReadDeviceConfigurationPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.DeviceConfiguration" }
    $PolicyReadIdentityProtectionPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.IdentityProtection" }
    $PolicyReadPermissionGrantPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "Policy.Read.PermissionGrant" }
    $SecurityActionsReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityActions.Read.All" }
    $SecurityAlertReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityAlert.Read.All" }
    $SecurityAnalyzedMessageReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityAnalyzedMessage.Read.All" }
    $SecurityEventsReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityEvents.Read.All" }
    $SecurityIdentitiesAccountReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityIdentitiesAccount.Read.All" }
    $SecurityIdentitiesHealthReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityIdentitiesHealth.Read.All" }
    $SecurityIdentitiesSensorsReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityIdentitiesSensors.Read.All" }
    $SecurityIdentitiesUserActionsReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityIdentitiesUserActions.Read.All" }
    $SecurityIncidentReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "SecurityIncident.Read.All" }
    $userReadPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "User.Read" }
    $userReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "User.Read.All" }
    $UserAuthenticationMethodReadAllPermission = $graphServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq "UserAuthenticationMethod.Read.All" }

    if (-not $ApplicationReadAllPermission -or -not $AuditLogReadAllPermission -or -not $PolicyReadAllPermission -or -not $userReadAllPermission -or -not $PolicyReadAuthenticationMethodPermission -or -not $PolicyReadConditionalAccessPermission -or -not $PolicyReadDeviceConfigurationPermission -or -not $PolicyReadIdentityProtectionPermission -or -not $PolicyReadPermissionGrantPermission -or -not $SecurityActionsReadAllPermission -or -not $SecurityAlertReadAllPermission -or -not $SecurityAnalyzedMessageReadAllPermission -or -not $SecurityEventsReadAllPermission -or -not $SecurityIdentitiesAccountReadAllPermission -or -not $SecurityIdentitiesHealthReadAllPermission -or -not $SecurityIdentitiesSensorsReadAllPermission -or -not $SecurityIdentitiesUserActionsReadAllPermission -or -not $SecurityIncidentReadAllPermission -or -not $userReadPermission -or -not $userReadAllPermission -or -not $UserAuthenticationMethodReadAllPermission) {
        Write-ColorOutput Red "Failed to find required permissions in Microsoft Graph!"
        Write-ColorOutput Yellow "Available OAuth2 permissions:"
        $graphServicePrincipal.Oauth2PermissionScopes | Select-Object Value, Id | Format-Table
        exit 1
    }
    
    Write-ColorOutput Green "Found required permissions:"
    Write-Host "  - Application.Read.All (Delegated): $($ApplicationReadAllPermission.Id)"
    Write-Host "  - AuditLog.Read.All (Delegated): $($AuditLogReadAllPermission.Id)"
    Write-Host "  - Directory.Read.All (Delegated): $($PolicyReadAllPermission.Id)"
    Write-Host "  - Policy.Read.All (Delegated): $($userReadAllPermission.Id)"
    Write-Host "  - Policy.Read.AuthenticationMethod (Delegated): $($PolicyReadAuthenticationMethodPermission.Id)"
    Write-Host "  - Policy.Read.ConditionalAccess (Delegated): $($PolicyReadConditionalAccessPermission.Id)"
    Write-Host "  - Policy.Read.DeviceConfiguration (Delegated): $($PolicyReadDeviceConfigurationPermission.Id)"
    Write-Host "  - Policy.Read.IdentityProtection (Delegated): $($PolicyReadIdentityProtectionPermission.Id)"
    Write-Host "  - Policy.Read.PermissionGrant (Delegated): $($PolicyReadPermissionGrantPermission.Id)"
    Write-Host "  - SecurityActions.Read.All (Delegated): $($SecurityActionsReadAllPermission.Id)"
    Write-Host "  - SecurityAlert.Read.All (Delegated): $($SecurityAlertReadAllPermission.Id)"
    Write-Host "  - SecurityAnalyzedMessage.Read.All (Delegated): $($SecurityAnalyzedMessageReadAllPermission.Id)"
    Write-Host "  - SecurityEvents.Read.All (Delegated): $($SecurityEventsReadAllPermission.Id)"
    Write-Host "  - SecurityIdentitiesAccount.Read.All (Delegated): $($SecurityIdentitiesAccountReadAllPermission.Id)"
    Write-Host "  - SecurityIdentitiesHealth.Read.All (Delegated): $($SecurityIdentitiesHealthReadAllPermission.Id)"
    Write-Host "  - SecurityIdentitiesSensors.Read.All (Delegated): $($SecurityIdentitiesSensorsReadAllPermission.Id)"
    Write-Host "  - SecurityIdentitiesUserActions.Read.All (Delegated): $($SecurityIdentitiesUserActionsReadAllPermission.Id)"
    Write-Host "  - SecurityIncident.Read.All (Delegated): $($SecurityIncidentReadAllPermission.Id)"
    Write-Host "  - User.Read (Delegated): $($UserReadPermission.Id)"
    Write-Host "  - User.Read.All (Delegated): $($UserReadAllPermission.Id)"
    Write-Host "  - UserAuthenticationMethod.Read.All (Delegated): $($UserAuthenticationMethodReadAllPermission.Id)"

    # Create the application registration
    Write-ColorOutput Yellow "Creating application registration: $AppName"
    
    $appRegistration = @{
        DisplayName = $AppName
        Description = "App registration created via PowerShell with User.Read and User.Read.All permissions"
        SignInAudience = "AzureADMyOrg"  # Single tenant
        RequiredResourceAccess = @(
            @{
                ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
                ResourceAccess = @(
                    @{
                        Id = $AuditLogReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $UserReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadAuthenticationMethodPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadConditionalAccessPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadDeviceConfigurationPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadIdentityProtectionPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $PolicyReadPermissionGrantPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityActionsReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityAlertReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityAnalyzedMessageReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityEventsReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityIdentitiesAccountReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityIdentitiesHealthReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityIdentitiesSensorsReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityIdentitiesUserActionsReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $SecurityIncidentReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $UserReadPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $UserReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    },
                    @{
                        Id = $UserAuthenticationMethodReadAllPermission.Id
                        Type = "Scope"  # Delegated permission
                    }
      
                )
            }
        )
        Web = @{
            RedirectUris = @("https://localhost:8080/auth/callback")
            ImplicitGrantSettings = @{
                EnableAccessTokenIssuance = $false
                EnableIdTokenIssuance = $false
            }
        }
        PublicClient = @{
            RedirectUris = @("http://localhost")
        }
    }
    
    # Create the application
    $app = New-MgApplication -BodyParameter $appRegistration
    
    Write-ColorOutput Green "Application registration created successfully!"
    Write-Host ""
    Write-ColorOutput Cyan "=== Application Details ==="
    Write-Host "Application Name: $($app.DisplayName)"
    Write-Host "Application ID: $($app.AppId)"
    Write-Host "Object ID: $($app.Id)"
    Write-Host "Created: $($app.CreatedDateTime)"
    Write-Host ""
    
    # Create a client secret (optional)
    Write-Host "Do you want to create a client secret? (y/N): " -NoNewline
    $createSecret = Read-Host
    
    if ($createSecret -eq 'y' -or $createSecret -eq 'Y') {
        Write-ColorOutput Yellow "Creating client secret..."
        
        $secretParams = @{
            PasswordCredential = @{
                DisplayName = "PowerShell Generated Secret"
                EndDateTime = (Get-Date).AddYears(1)  # 1 year expiration
            }
        }
        
        $secret = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretParams
        
        Write-ColorOutput Green "Client secret created successfully!"
        Write-ColorOutput Red "IMPORTANT: Save this client secret value - it won't be shown again!"
        Write-Host ""
        Write-ColorOutput Cyan "=== Client Secret Details ==="
        Write-Host "Secret ID: $($secret.KeyId)"
        Write-Host "Secret Value: $($secret.SecretText)"
        Write-Host "Expires: $($secret.EndDateTime)"
        Write-Host ""
        Write-ColorOutput Red "Store the secret value securely - you won't be able to retrieve it later!"
    }
    
    # Create service principal (for admin consent)
    Write-ColorOutput Yellow "Creating service principal..."
    try {
        $servicePrincipal = New-MgServicePrincipal -AppId $app.AppId
        Write-ColorOutput Green "Service principal created successfully!"
        Write-Host "Service Principal ID: $($servicePrincipal.Id)"
    } catch {
        Write-ColorOutput Red "Failed to create service principal: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-ColorOutput Cyan "=== Next Steps ==="
    Write-Host "1. Admin consent may be required for User.Read.All permissions"
    Write-Host "2. Go to Azure Portal > App registrations > $AppName > API permissions"
    Write-Host "3. Click 'Grant admin consent for [your organization]'"
    Write-Host "4. The application is now ready to use!"
    Write-Host ""
    Write-ColorOutput Yellow "Azure Portal URL:"
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$($app.AppId)"
    
} catch {
    Write-ColorOutput Red "Error occurred: $($_.Exception.Message)"
    Write-ColorOutput Red "Stack trace: $($_.ScriptStackTrace)"
    exit 1
} finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph | Out-Null
        Write-ColorOutput Yellow "Disconnected from Microsoft Graph."
    } catch {
        # Ignore disconnect errors
    }
}

Write-ColorOutput Green "Script completed successfully!"

# Example usage:
# .\Create-AppRegistration.ps1 -AppName "MyTestApp"
# .\Create-AppRegistration.ps1 -AppName "MyTestApp" -TenantId "your-tenant-id"
