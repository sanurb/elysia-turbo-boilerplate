import "dotenv/config"
import { defineConfig } from "drizzle-kit"
import type { Config } from 'drizzle-kit';

export default defineConfig({
    out: "./drizzle",
    schema: "./src/db/schema.ts",
    dialect: "postgresql",
    dbCredentials: {
        url: process.env.DATABASE_URL!,
    },
    verbose: true,
    breakpoints: true,
} satisfies Config)
