# rust-saas

**rust-saas** is a full-stack Rust platform for building multi-tenant SaaS applications.

It combines an isomorphic Leptos frontend, an Axum-based backend, PostgreSQL persistence, and Casbin-powered authorization. The project is organized as a Cargo workspace with clearly separated crates for shared domain types, authorization, database infrastructure, application bootstrap, and the web application.

## Features

- Multi-tenant architecture with tenants and workspaces
- Identity-first user model
- Email and password authentication
- Argon2 password hashing
- JWT-based sessions stored in HTTP-only cookies
- Domain-scoped RBAC authorization with Casbin
- Platform, tenant, and workspace authorization domains
- Leptos server-side rendering and client hydration
- Server functions for frontend-to-backend communication
- PostgreSQL migrations with SQLx
- Reproducible local development with Docker Compose
- Database seed command for bootstrap data
- Tailwind CSS v4 styling

## Architecture

The repository uses a Cargo workspace:

```text
crates/
├── core/     Shared domain types and identifiers
├── authz/    Casbin-based authorization service
├── db/       PostgreSQL connection and migrations
├── seed/     Bootstrap data and demo accounts
└── app/      Leptos UI, Axum server, server functions
```

The application separates three concerns:

| Concern | Responsibility |
|---|---|
| Authentication | Establishes who the user is |
| Authorization | Determines what the user is allowed to do |
| Data isolation | Ensures users only access data belonging to their tenant or workspace |

### Multi-tenancy model

```text
platform
└── tenant
    ├── workspace
    └── workspace
```

- A **tenant** represents a customer organization.
- A **workspace** represents a working area inside a tenant, such as a team, department, or project.
- A **user** is a global identity and can participate in multiple tenants or workspaces.
- A **workspace** contains business resources such as documents.

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

Example roles:

- `platform_admin`
- `tenant_owner`
- `workspace_admin`
- `editor`
- `viewer`

## Technology stack

| Layer | Technology |
|---|---|
| Language | Rust |
| UI | Leptos |
| Backend | Axum |
| Database | PostgreSQL |
| Database access | SQLx |
| Authorization | Casbin |
| Authentication | Argon2, JSON Web Tokens |
| Styling | Tailwind CSS |
| Local infrastructure | Docker Compose |

## Getting started

### Prerequisites

- Rust
- `wasm32-unknown-unknown` target
- `cargo-leptos`
- Docker and Docker Compose

Install the WebAssembly target and Leptos CLI:

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-leptos
```

### Start PostgreSQL

```bash
docker compose up -d
```

### Configure environment

Copy the example environment file:

```bash
cp .env.example .env
```

## Генерация JWT_SECRET

Для локальной разработки:

```bash
openssl rand -base64 48
```

Или на Windows PowerShell:

```powershell
[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
```

Полученное значение вставьте в `.env`:

```env
JWT_SECRET=your-generated-random-secret
```

В `.env.example` оставьте placeholder (replace-with-a-long-random-secret) — не реальный секрет.

Then adjust the values as needed:

```env
DATABASE_URL=postgres://user:password@localhost:5432/rust_saas
JWT_SECRET=replace-with-a-long-random-secret
BIND_ADDR=127.0.0.1:3395
```

### Apply migrations and seed data

```bash
cargo run -p seed
```

Тестовые пользователи:

| Роль | Email | Пароль |
|---|---|---|
| Platform admin | `platform-admin@example.test` | `PlatformAdmin123!` |
| Tenant owner | `owner@acme.test` | `Owner123!` |
| Workspace editor | `editor@acme.test` | `Editor123!` |

This command applies database migrations and creates initial platform, tenant, workspace, user, and authorization data.

### Run the application

```bash
cargo leptos watch
```

Open:

```text
http://127.0.0.1:3395
```

## Project layout

```text
.
├── Cargo.toml
├── docker-compose.yml
├── .env.example
└── crates/
    ├── core/
    ├── authz/
    ├── db/
    ├── seed/
    └── app/
```

### core

Contains shared domain types such as users, tenants, workspaces, documents, and authorization domain helpers.

This crate intentionally has no dependencies on SQLx, Casbin, Axum, or Leptos.

### authz

Contains the Casbin model, authorization service, role definitions, and policy management API.

Business code should not use Casbin directly. It should call the authorization service instead.

### db

Contains PostgreSQL connection helpers and SQL migrations.

### seed

Contains a standalone binary for creating initial platform, tenant, workspace, user, and policy data.

### app

Contains the Leptos application, Axum server, server functions, pages, and HTTP application state.

## Authorization model

The project uses Casbin RBAC with domains.

A request is represented as:

```text
subject, domain, object, action
```

Examples:

```text
user_id, platform, tenants, create
user_id, tenant:uuid, workspaces, create
user_id, workspace:uuid, documents, write
```

Authorization is always checked on the server before business logic executes.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- Prefer explicit roles and permissions over unrestricted superuser access.

## Roadmap

- Invitation-based workspace membership
- Role management UI
- Platform administration dashboard
- Audit logging
- Refresh tokens and session management
- API keys
- Integration tests for cross-tenant access
- Production deployment configuration
- Observability and metrics

## License

Choose and add a license before publishing the repository.