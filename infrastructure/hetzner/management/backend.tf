terraform {
  # PG_CONN_STR and PGPASSWORD are supplied only by the runtime environment.
  # Ansible pre-creates the exact schema/table/index so this backend role never
  # receives DDL privileges. Activation remains gated on TLS, locking and state
  # source evidence; do not run terraform init -migrate-state here.
  backend "pg" {
    schema_name          = "terraform_management"
    skip_schema_creation = true
    skip_table_creation  = true
    skip_index_creation  = true
  }
}
