terraform {
  required_version = "= 1.15.5"

  backend "pg" {
    schema_name          = "terraform_lock_probe"
    skip_schema_creation = true
    skip_table_creation  = true
    skip_index_creation  = true
  }
}
