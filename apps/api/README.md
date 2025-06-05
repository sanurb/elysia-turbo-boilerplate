# API (Elysia + Bun)

This is the `api` backend app for the monorepo, built with [Elysia](https://elysiajs.com/) and running on [Bun](https://bun.sh/).

## Development

To start the development server:

```bash
bun run dev
```

The server will be available at http://localhost:3000/

## Build

To build the app for production:

```bash
bun run build
```

## Monorepo Context

This app lives in the `apps/api` directory and is managed by Turbo. See the root `package.json` and Turbo docs for more details.
