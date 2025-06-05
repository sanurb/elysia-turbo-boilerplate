import { drizzle } from 'drizzle-orm/bun-sql';
import { SQL } from 'bun';

const connectionString = process.env.DATABASE_URL!;

if (!connectionString) {
  throw new Error('DATABASE_URL is not set in environment variables');
}

const client = new SQL(process.env.DATABASE_URL!);
export const db = drizzle({client}); 