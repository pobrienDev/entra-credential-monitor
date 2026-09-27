output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "function_app_name" {
  value = azurerm_function_app_flex_consumption.main.name
}

output "storage_account_name" {
  value = azurerm_storage_account.main.name
}

output "managed_identity_principal_id" {
  description = "Object ID of the identity that holds the Graph permissions."
  value       = azurerm_function_app_flex_consumption.main.identity[0].principal_id
}

output "granted_graph_permissions" {
  value = sort(keys(azuread_app_role_assignment.graph))
}
