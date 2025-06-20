import 'dotenv/config';
import { drizzle } from "drizzle-orm/node-postgres"
import { Client } from "pg";
import * as schema from './schema';

const client = new Client({
    connectionString: process.env.DATABASE_URL,
});

export const db = drizzle({
    client,
    casing: "snake_case",
    schema: {
        ...schema
    }
});
