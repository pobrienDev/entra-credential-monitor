# Azure Functions variant: timer trigger + system-assigned managed identity.
# No secrets anywhere: storage is accessed with the identity (shared keys are
# disabled, so none exist to end up in state), and Graph consent is granted to
# the identity's service principal exactly as for credmon-reader.

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  suffix = random_string.suffix.result
  tags = {
    project    = "entra-credential-monitor"
    managed_by = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.name_prefix}"
  location = var.location
  tags     = local.tags
}

# --- Storage: host storage for the Functions runtime, deployment package, reports

resource "azurerm_storage_account" "main" {
  name                            = "st${var.name_prefix}${local.suffix}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # identity only; nothing key-shaped in state
  tags                            = local.tags
}

resource "azurerm_storage_container" "deployments" {
  name               = "deployments"
  storage_account_id = azurerm_storage_account.main.id
}

resource "azurerm_storage_container" "reports" {
  name               = "reports"
  storage_account_id = azurerm_storage_account.main.id
}

# --- Observability

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${var.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "appi-${var.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "other"
  tags                = local.tags
}

# --- Function App on Flex Consumption

resource "azurerm_service_plan" "main" {
  name                = "plan-${var.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = local.tags
}

resource "azurerm_function_app_flex_consumption" "main" {
  name                = "func-${var.name_prefix}-${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id
  tags                = local.tags

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${azurerm_storage_account.main.primary_blob_endpoint}${azurerm_storage_container.deployments.name}"
  storage_authentication_type = "SystemAssignedIdentity"

  runtime_name           = "python"
  runtime_version        = "3.12"
  maximum_instance_count = 40
  instance_memory_in_mb  = 2048
  https_only             = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_insights_connection_string = azurerm_application_insights.main.connection_string
    minimum_tls_version                    = "1.2"
  }

  app_settings = {
    # Host storage via identity: the runtime reads this instead of a connection string.
    AzureWebJobsStorage__accountName = azurerm_storage_account.main.name
    CREDMON_STORAGE_ACCOUNT          = azurerm_storage_account.main.name
    CREDMON_REPORTS_CONTAINER        = azurerm_storage_container.reports.name
  }
}

# --- Storage access for the identity (host storage, deployment package, reports)

resource "azurerm_role_assignment" "func_blob_owner" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = azurerm_function_app_flex_consumption.main.identity[0].principal_id
}

resource "azurerm_role_assignment" "func_queue" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Queue Data Contributor"
  principal_id         = azurerm_function_app_flex_consumption.main.identity[0].principal_id
}

resource "azurerm_role_assignment" "func_table" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_function_app_flex_consumption.main.identity[0].principal_id
}

# Whoever runs Terraform and deploy.sh needs to upload the package with the CLI.
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "deployer_blob" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# --- Graph consent for the managed identity, same two read-only permissions as credmon-reader

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_app_role_assignment" "graph" {
  for_each = toset(var.graph_app_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azurerm_function_app_flex_consumption.main.identity[0].principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}
