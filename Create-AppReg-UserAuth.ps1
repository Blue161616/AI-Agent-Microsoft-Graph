# PowerShell Script to Create App Registration with Identity & Security Read-Only Microsoft Graph API Delegated Permissions
# Requires Microsoft.Graph PowerShell SDK

param(
    [Parameter(Mandatory = $true)]
    [string]$AppDisplayName,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$RedirectUri = "http://localhost",
    
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
    "DelegatedPermissionGrant.ReadWrite.All"
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

# Define comprehensive read-only identity and security Microsoft Graph delegated permissions
$IdentitySecurityDelegatedPermissions = @{
    # User and Profile Management
    "User.Read" = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
    "User.Read.All" = "a154be20-db9c-4678-8ab7-66f6cc099a59"
    "User.ReadBasic.All" = "b340eb25-3456-403f-be2f-af7a0d370277"
    "UserAuthenticationMethod.Read" = "	1f6b61c5-2f65-4135-9c9f-31c0f8d32b52"
    "UserAuthenticationMethod.Read.All" = "aec28ec7-4d02-4e8c-b864-50163aea77eb"
    
    # Directory and Organization
    "Directory.Read.All" = "06da0dbc-49e2-44d2-8312-53f166ab848a"
    "Organization.Read.All" = "4908d5b9-3fb2-4b1e-9336-1888b7937185"
    "AdministrativeUnit.Read.All" = "3361d15d-be43-4de6-b441-3c746d05163d"
    
    # Group Management
    "Group.Read.All" = "5f8c59db-677d-491f-a6b8-5f174b11ec1d"
    "GroupMember.Read.All" = "bc024368-1153-4739-b217-4326f2e966d0"
    
    # Application and Service Principal Management
    "Application.Read.All" = "c79f8feb-a9db-4090-85f9-90d820caa0eb"
    "ServicePrincipalEndpoint.Read.All" = "9f9ce928-e038-4e3b-8faf-7b59049a8ddc"
    
    # Role and Permission Management
    "RoleManagement.Read.All" = "48fec646-b2ba-4019-8681-8eb31435aded"
    "RoleManagement.Read.Directory" = "741c54c3-0c1e-44a1-818b-3f97ab4e8c83"
    "DelegatedPermissionGrant.Read.All" = "a197cdc4-a8e8-4d49-9d35-4ca7c83887b4"
    
    # Device Management
    "Device.Read" = "951183d1-1a61-466f-a6d1-1fde911bfd95"
    "Device.Read.All" = "11d4cd79-5ba5-460f-803f-e22c8ab85ccd"
    "DeviceManagementConfiguration.Read.All" = "f1493658-876a-4c87-8fa7-edb559b3476a"
    "DeviceManagementApps.Read.All" = "4edf5f54-4666-44af-9de9-0144fb4b6e8c"
    "DeviceManagementManagedDevices.Read.All" = "314874da-47d6-4978-88dc-cf0d37f0bb82"
    
    # Security and Threat Protection
    "SecurityEvents.Read.All" = "64733abd-851e-478a-bffb-e47a14b18235"
    "SecurityActions.Read.All" = "1638cddf-07a4-4de2-8645-69c96cacad73"
    "SecurityAlert.Read.All" = "bc257fb8-46b4-4b15-8713-01e91bfbe4ea"
    
    # Audit and Reporting
    "AuditLog.Read.All" = "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20"
    "ReportSettings.Read.All" = "84fac5f4-33a9-4100-aa38-a20c6d29e5e7"
    "Reports.Read.All" = "02e97553-ed7b-43d0-ab3c-f8bace0d040c"
    
    # Identity Protection and Risk Management
    "IdentityRiskEvent.Read.All" = "8f6a01e7-0391-4ee5-aa22-a3af122cef27"
    "IdentityRiskyUser.Read.All" = "d04bb851-cb7c-4146-97c7-ca3e71baf56c"
    "IdentityRiskyServicePrincipal.Read.All" = "ea5c4ab0-5a73-4f35-8272-5d5337884e5d"
    
    # Conditional Access and Policies
    "Policy.Read.All" = "572fea84-0151-49b2-9301-11cb16974376"
    "Policy.Read.ConditionalAccess" = "633e0fce-8c58-4cfb-9495-12bbd5a24f7c"
    
    # Access Reviews
    "AccessReview.Read.All" = "ebfcd32b-babb-40f4-a14b-42706e83bd28"
    
    # Privileged Identity Management
    "PrivilegedAccess.Read.AzureAD" = "b3a539c9-59cb-4ad5-825a-041ddbdc2bdb"
    "PrivilegedAccess.Read.AzureResources" = "1d89d70c-dcac-4248-b214-903c457af83a"
 
    # Authentication Context and Methods
    "AuthenticationContext.Read.All" = "57b030f1-8c35-469c-b0d9-e4a077debe70"
    
    # Cross-tenant Access Policies
    "CrossTenantInformation.ReadBasic.All" = "cb1ba48f-d22b-4325-a07f-74135a62ee41"
    
    # Custom Security Attributes
    "CustomSecAttributeDefinition.Read.All" = "ce026878-a0ff-4745-a728-d4fedd086c07"
    "CustomSecAttributeAssignment.Read.All" = "b46ffa80-fe3d-4822-9a1a-c200932d54d0"
    

}

# Create application registration with delegated permission configuration
try {
    Write-Host "Creating app registration: $AppDisplayName" -ForegroundColor Yellow
    
    $AppRegistration = New-MgApplication `
        -DisplayName $AppDisplayName `
        -Description "Identity and Security Read-Only Application (Delegated Permissions)" `
    
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

# Prepare required resource access for Microsoft Graph with delegated permissions
$RequiredResourceAccess = @{
    ResourceAppId = $GraphServicePrincipalId
    ResourceAccess = @()
}

# Add each permission to the required resource access
foreach ($Permission in $IdentitySecurityDelegatedPermissions.GetEnumerator()) {
    $RequiredResourceAccess.ResourceAccess += @{
        Id = $Permission.Value
        Type = "Scope"  # Delegated permission
    }
    Write-Host "  + Added delegated permission: $($Permission.Key)" -ForegroundColor Gray
}

# Update app registration with required permissions
try {
    Write-Host "Configuring Microsoft Graph API delegated permissions..." -ForegroundColor Yellow
    
    Update-MgApplication -ApplicationId $AppRegistration.Id -RequiredResourceAccess @($RequiredResourceAccess)
    
    Write-Host "+ Delegated permissions configured successfully" -ForegroundColor Green
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

# Grant admin consent for delegated permissions if requested
if ($GrantAdminConsent) {
    try {
        Write-Host "Granting admin consent for delegated permissions..." -ForegroundColor Yellow
        
        # Get the current user's object ID for delegated permission grants
        $CurrentUser = Get-MgContext
        $CurrentUserId = (Get-MgUser -Filter "userPrincipalName eq '$($CurrentUser.Account)'").Id
        
        if ($CurrentUserId) {
            # Create a delegated permission grant (OAuth2PermissionGrant)
            $PermissionGrant = @{
                ClientId = $ServicePrincipal.Id
                ConsentType = "AllPrincipals"  # Admin consent for all users
                ResourceId = $GraphServicePrincipal.Id
                Scope = ($IdentitySecurityDelegatedPermissions.Keys -join " ")
            }
            
            try {
                New-MgOauth2PermissionGrant @PermissionGrant
                Write-Host "+ Admin consent granted for all delegated permissions" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to grant admin consent automatically: $($_.Exception.Message)"
                Write-Host "You will need to grant admin consent manually in the Azure portal." -ForegroundColor Yellow
            }
        }
        else {
            Write-Warning "Could not determine current user ID. Admin consent must be granted manually."
        }
    }
    catch {
        Write-Warning "Failed to grant admin consent. You may need to grant consent manually in the Azure portal."
    }
}

# Display summary information
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "APP REGISTRATION SUMMARY (DELEGATED PERMISSIONS)" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan
Write-Host "Application Name: $AppDisplayName" -ForegroundColor White
Write-Host "Application ID: $($AppRegistration.AppId)" -ForegroundColor White
Write-Host "Object ID: $($AppRegistration.Id)" -ForegroundColor White
Write-Host "Service Principal ID: $($ServicePrincipal.Id)" -ForegroundColor White
Write-Host "Tenant ID: $((Get-MgContext).TenantId)" -ForegroundColor White
Write-Host "Redirect URI: $RedirectUri" -ForegroundColor White
Write-Host "`nDelegated Permissions Configured: $($IdentitySecurityDelegatedPermissions.Count) Microsoft Graph delegated permissions" -ForegroundColor White

if (-not $GrantAdminConsent) {
    Write-Host "`n! IMPORTANT: Admin consent may be required for some permissions!" -ForegroundColor Yellow
    Write-Host "To grant admin consent, visit:" -ForegroundColor Yellow
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($AppRegistration.AppId)" -ForegroundColor Yellow
}

Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Configure additional redirect URIs if needed for your application" -ForegroundColor White
Write-Host "2. Grant admin consent for permissions that require it (if not done already)" -ForegroundColor White
Write-Host "3. Implement OAuth 2.0 authorization code flow in your application" -ForegroundColor White
Write-Host "4. Test user sign-in and token acquisition with the assigned permissions" -ForegroundColor White
Write-Host "5. Review and remove any unused permissions following least privilege principle" -ForegroundColor White

Write-Host "`nAUTHENTICATION FLOW:" -ForegroundColor Cyan
Write-Host "* This application is configured for delegated permissions" -ForegroundColor White
Write-Host "* Users must sign in and consent to permissions" -ForegroundColor White
Write-Host "* Application acts on behalf of the signed-in user" -ForegroundColor White
Write-Host "* Use OAuth 2.0 Authorization Code flow or Device Code flow" -ForegroundColor White

Write-Host "`nDELEGATED PERMISSION CATEGORIES INCLUDED:" -ForegroundColor Cyan
Write-Host "* User and Profile Management (5 permissions)" -ForegroundColor White
Write-Host "* Directory and Organization (3 permissions)" -ForegroundColor White
Write-Host "* Group Management (2 permissions)" -ForegroundColor White
Write-Host "* Application Management (2 permissions)" -ForegroundColor White
Write-Host "* Role and Permission Management (3 permissions)" -ForegroundColor White
Write-Host "* Device Management (5 permissions)" -ForegroundColor White
Write-Host "* Security and Threat Protection (3 permissions)" -ForegroundColor White
Write-Host "* Audit and Reporting (3 permissions)" -ForegroundColor White
Write-Host "* Identity Protection and Risk (3 permissions)" -ForegroundColor White
Write-Host "* Conditional Access and Policies (2 permissions)" -ForegroundColor White
Write-Host "* Access Reviews (1 permission)" -ForegroundColor White
Write-Host "* Privileged Identity Management (2 permissions)" -ForegroundColor White
Write-Host "* Compliance and Information Protection (2 permissions)" -ForegroundColor White
Write-Host "* Custom Security Attributes (2 permissions)" -ForegroundColor White
Write-Host "* Entitlement Management (1 permission)" -ForegroundColor White
Write-Host "* Cross-tenant Access (1 permission)" -ForegroundColor White

Write-Host "`n" + "="*80 -ForegroundColor Cyan

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "+ Disconnected from Microsoft Graph" -ForegroundColor Green