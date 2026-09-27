variable "tenant_id" {
  description = "Entra tenant the function scans and authenticates against."
  type        = string
}

variable "subscription_id" {
  description = "Azure subscription to deploy into."
  type        = string
}

variable "location" {
  description = "Region with Flex Consumption support."
  type        = string
  default     = "westus2"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "credmon"
}

variable "graph_app_roles" {
  description = "Read-only Graph application permissions granted to the function's managed identity."
  type        = list(string)
  default     = ["Application.Read.All", "User.ReadBasic.All"]
}
