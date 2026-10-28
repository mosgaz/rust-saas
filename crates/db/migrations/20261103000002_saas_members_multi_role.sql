-- Multi-role memberships (owner: `saas`; see ADR-0001, handoff §7, §8).
--
-- Under domain-ownership RBAC, a user can hold several roles in the same
-- scope (tenant or workspace). The primary key is extended with `role`:
--
--   before: PRIMARY KEY (scope_id, user_id)
--   after:  PRIMARY KEY (scope_id, user_id, role)
--
-- `assign_role` uses `INSERT ... ON CONFLICT DO NOTHING`; `revoke_role`
-- deletes a specific `(scope_id, user_id, role)` row.

alter table tenant_members drop constraint tenant_members_pkey;
alter table tenant_members add primary key (tenant_id, user_id, role);

alter table workspace_members drop constraint workspace_members_pkey;
alter table workspace_members add primary key (workspace_id, user_id, role);