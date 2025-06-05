# Architecture Overview

## Monorepo Structure

```mermaid
flowchart TD
    Root[Project Root]
    Root --> Apps[apps/]
    Root --> Packages[packages/]
    Root --> Docs[docs/]
    Root --> Tasks[tasks/]
    Apps --> API[api (Elysia backend)]
    Apps --> Web[web (Frontend)]
    Apps --> DocsApp[docs (Docs Site)]
    Packages --> UI[ui]
    Packages --> ESLint[eslint-config]
    Packages --> TSConfig[typescript-config]
```

## API App (Elysia Backend)

- **Location:** `apps/api`
- **Framework:** [Elysia](https://elysiajs.com/) running on [Bun](https://bun.sh/)
- **Purpose:** Provides backend API endpoints for the system
- **Key Endpoints:**
  - `/` — Welcome route
  - `/health` — Health check (returns `{ status: "ok" }`)
- **Port:** 3000 (default)
- **Scripts:**
  - `bun run dev` — Start development server
  - `bun run build` — Build for production

## Data Flow & Extensibility
- The API app is designed to be stateless and easily extensible for new routes and features.
- Future integrations (e.g., database, authentication) should be added as new modules or middleware within `apps/api`.

---

*Update this document as the architecture evolves or new services are added.*
