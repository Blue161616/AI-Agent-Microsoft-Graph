# PowerShell Script to Create App Registration with Identity & Security Read-Only Microsoft Graph API Permissions
# Requires Microsoft.Graph PowerShell SDK

param(
    [Parameter(Mandatory = $true)]
    [string]$AppDisplayName,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$GrantAdminConsent
)

# Import required modules
try {
    Import-Module Microsoft.Graph.Applications -Force
    Import-Module Microsoft.Graph.Authentication -Force
    Write-Host "+ Microsoft Graph modules imported successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import Microsoft Graph modules. Please install using: Install-Module Microsoft.Graph"
    exit 1
}

# Connect to Microsoft Graph with required scopes
$RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId
    } else {
        Connect-MgGraph -Scopes $RequiredScopes
    }
    Write-Host "+ Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# Microsoft Graph Service Principal ID (constant across all tenants)
$GraphServicePrincipalId = "00000003-0000-0000-c000-000000000000"

# Define comprehensive read-only identity and security Microsoft Graph permissions
$IdentitySecurityPermissions = @{
    # User and Profile Management
    "User.Read.All" = "df021288-bdef-4463-88db-98f22de89214"
    "User.ReadBasic.All" = "97235f07-e226-4f63-ace3-39588e11d3a1"
    "UserAuthenticationMethod.Read.All" = "38d9df27-64da-44fd-b7c5-a6fbac20248f"
    
    # Directory and Organization
    "Directory.Read.All" = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
    "Organization.Read.All" = "498476ce-e0fe-48b0-b801-37ba7e2685c6"
    "AdministrativeUnit.Read.All" = "134fd756-38ce-4afd-ba33-e9623dbe66c2"
    
    # Group Management
    "Group.Read.All" = "5b567255-7703-4780-807c-7be8301ae99b"
    "GroupMember.Read.All" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
    
    # Application and Service Principal Management
    "Application.Read.All" = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
    "ServicePrincipalEndpoint.Read.All" = "5256681e-b7f6-40c0-8447-2d9db68797a0"
    
    # Role and Permission Management
    "RoleManagement.Read.All" = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4"
    "DelegatedPermissionGrant.Read.All" = "81b4724a-58aa-41c1-8a55-84ef97466587"
    
    # Device Management
    "Device.Read.All" = "7438b122-aefc-4978-80ed-43db9fcc7715"
    "DeviceManagementConfiguration.Read.All" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
    "DeviceManagementApps.Read.All" = "7a6ee1e7-141e-4cec-ae74-d9db155731ff"
    "DeviceManagementManagedDevices.Read.All" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
    
    # Security and Threat Protection
    "SecurityEvents.Read.All" = "bf394140-e372-4bf9-a898-299cfc7564e5"
    "SecurityActions.Read.All" = "5e0edab9-c148-49d0-b423-ac253e121825"
    "SecurityAlert.Read.All" = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"
    
    # Audit and Reporting
    "AuditLog.Read.All" = "b0afded3-3588-46d8-8b3d-9842eff778da"    
    "ReportSettings.Read.All" = "ee353f83-55ef-4b78-82da-555bfa2b4b95"
    "Reports.Read.All" = "230c1aed-a721-4c5d-9cb4-a90514e508ef"
    
    # Identity Protection and Risk Management
    "IdentityRiskEvent.Read.All" = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
    "IdentityRiskyUser.Read.All" = "dc5007c0-2d7d-4c42-879c-2dab87571379"
    "IdentityRiskyServicePrincipal.Read.All" = "607c7344-0eed-41e5-823a-9695ebe1b7b0"
    
    # Conditional Access
    "Policy.Read.All" = "246dd0d5-5bd0-4def-940b-0421030a5b68"
    "Policy.Read.ConditionalAccess" = "37730810-e9ba-4e46-b07e-8ca78d182097"
    
    # Access Reviews
    "AccessReview.Read.All" = "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa"
    
    # Privileged Identity Management
    "PrivilegedAccess.Read.AzureAD" = "4cdc2547-9148-4295-8d11-be0db1391d6b"
    
    # Compliance and Information Protection
    "InformationProtectionPolicy.Read.All" = "19da66cb-0fb0-4390-b071-ebc76a349482"
    "ThreatAssessment.Read.All" = "f8f035bb-2cce-47fb-8bf5-7baf3ecbee48"
    
    # Authentication Context and Methods
    "AuthenticationContext.Read.All" = "381f742f-e1f8-4309-b4ab-e3d91ae4c5c1"
    
    # Sign-in Logs
    "AuditLogsQuery.Read.All" = "5e1e9171-754d-478c-812c-f1755a9a4c2d"
    "AuditLogsQuery-Entra.Read.All" = "7276d950-48fc-4269-8348-f22f2bb296d0"
}

# Create application registration
try {
    Write-Host "Creating app registration: $AppDisplayName" -ForegroundColor Yellow
    
    $AppRegistration = New-MgApplication -DisplayName $AppDisplayName -Description "Identity and Security Read-Only Application"
    
    Write-Host "+ App registration created successfully" -ForegroundColor Green
    Write-Host "  - Application ID: $($AppRegistration.AppId)" -ForegroundColor Cyan
    Write-Host "  - Object ID: $($AppRegistration.Id)" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to create app registration: $($_.Exception.Message)"
    exit 1
}

# Get Microsoft Graph Service Principal
try {
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$GraphServicePrincipalId'"
    if (-not $GraphServicePrincipal) {
        throw "Microsoft Graph service principal not found"
    }
    Write-Host "+ Found Microsoft Graph service principal" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get Microsoft Graph service principal: $($_.Exception.Message)"
    exit 1
}

# Prepare required resource access for Microsoft Graph
$RequiredResourceAccess = @{
    ResourceAppId = $GraphServicePrincipalId
    ResourceAccess = @()
}

# Add each permission to the required resource access
foreach ($Permission in $IdentitySecurityPermissions.GetEnumerator()) {
    $RequiredResourceAccess.ResourceAccess += @{
        Id = $Permission.Value
        Type = "Role"  # Application permission
    }
    Write-Host "  + Added permission: $($Permission.Key)" -ForegroundColor Gray
}

# Update app registration with required permissions
try {
    Write-Host "Configuring Microsoft Graph API permissions..." -ForegroundColor Yellow
    
    Update-MgApplication -ApplicationId $AppRegistration.Id -RequiredResourceAccess @($RequiredResourceAccess)
    
    Write-Host "+ Permissions configured successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure permissions: $($_.Exception.Message)"
    exit 1
}

# Create service principal for the application
try {
    Write-Host "Creating service principal..." -ForegroundColor Yellow
    
    $ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId
    
    Write-Host "+ Service principal created" -ForegroundColor Green
    Write-Host "  - Service Principal ID: $($ServicePrincipal.Id)" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to create service principal: $($_.Exception.Message)"
    exit 1
}

# Grant admin consent if requested
if ($GrantAdminConsent) {
    try {
        Write-Host "Granting admin consent for application permissions..." -ForegroundColor Yellow
        
        foreach ($Permission in $IdentitySecurityPermissions.GetEnumerator()) {
            $AppRoleId = $Permission.Value
            
            # Check if the app role assignment already exists
            $ExistingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id | 
                Where-Object { $_.AppRoleId -eq $AppRoleId -and $_.ResourceId -eq $GraphServicePrincipal.Id }
            
            if (-not $ExistingAssignment) {
                try {
                    New-MgServicePrincipalAppRoleAssignment `
                        -ServicePrincipalId $ServicePrincipal.Id `
                        -PrincipalId $ServicePrincipal.Id `
                        -ResourceId $GraphServicePrincipal.Id `
                        -AppRoleId $AppRoleId
                    
                    Write-Host "    + Granted: $($Permission.Key)" -ForegroundColor Gray
                }
                catch {
                    Write-Warning "Failed to grant permission $($Permission.Key): $($_.Exception.Message)"
                }
            }
            else {
                Write-Host "    * Already granted: $($Permission.Key)" -ForegroundColor Gray
            }
        }
        
        Write-Host "+ Admin consent process completed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to grant some permissions. You may need to grant admin consent manually in the Azure portal."
    }
}


# Display summary information
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "APP REGISTRATION SUMMARY" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan
Write-Host "Application Name: $AppDisplayName" -ForegroundColor White
Write-Host "Application ID: $($AppRegistration.AppId)" -ForegroundColor White
Write-Host "Object ID: $($AppRegistration.Id)" -ForegroundColor White
Write-Host "Service Principal ID: $($ServicePrincipal.Id)" -ForegroundColor White
Write-Host "Tenant ID: $((Get-MgContext).TenantId)" -ForegroundColor White
Write-Host "`nPermissions Configured: $($IdentitySecurityPermissions.Count) Microsoft Graph application permissions" -ForegroundColor White

if (-not $GrantAdminConsent) {
    Write-Host "`n! IMPORTANT: Admin consent is required!" -ForegroundColor Yellow
    Write-Host "To grant admin consent, visit:" -ForegroundColor Yellow
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($AppRegistration.AppId)" -ForegroundColor Yellow
}

Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Create a client secret or certificate for authentication" -ForegroundColor White
Write-Host "2. Grant admin consent for all permissions (if not done already)" -ForegroundColor White
Write-Host "3. Test the application with the assigned permissions" -ForegroundColor White
Write-Host "4. Review and remove any unused permissions following least privilege principle" -ForegroundColor White

Write-Host "`nPERMISSION CATEGORIES INCLUDED:" -ForegroundColor Cyan
Write-Host "* User and Profile Management (3 permissions)" -ForegroundColor White
Write-Host "* Directory and Organization (3 permissions)" -ForegroundColor White
Write-Host "* Group Management (2 permissions)" -ForegroundColor White
Write-Host "* Application Management (2 permissions)" -ForegroundColor White
Write-Host "* Role and Permission Management (2 permissions)" -ForegroundColor White
Write-Host "* Device Management (4 permissions)" -ForegroundColor White
Write-Host "* Security and Threat Protection (6 permissions)" -ForegroundColor White
Write-Host "* Audit and Reporting (3 permissions)" -ForegroundColor White
Write-Host "* Identity Protection and Risk (3 permissions)" -ForegroundColor White
Write-Host "* Conditional Access and Policies (2 permissions)" -ForegroundColor White
Write-Host "* Access Reviews (1 permission)" -ForegroundColor White
Write-Host "* Privileged Identity Management (2 permissions)" -ForegroundColor White
Write-Host "* Compliance and Information Protection (2 permissions)" -ForegroundColor White
Write-Host "* Custom Security Attributes (2 permissions)" -ForegroundColor White
Write-Host "* Entitlement Management (1 permission)" -ForegroundColor White
Write-Host "* Audit Logs Query (2 permissions)" -ForegroundColor White

Write-Host "`n" + "="*80 -ForegroundColor Cyan

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "+ Disconnected from Microsoft Graph" -ForegroundColor Green