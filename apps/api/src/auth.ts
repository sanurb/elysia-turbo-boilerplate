import { betterAuth } from 'better-auth';
import { openAPI, organization } from 'better-auth/plugins';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import { users, organizations, sessions } from './db/schema';

/**
 * Better Auth configuration with Drizzle ORM and organizations plugin.
 * Uses the official Drizzle adapter for full compatibility and performance.
 * - provider: 'pg' for PostgreSQL
 * - usePlural: true since all tables use plural names
 */
export const auth = betterAuth({
    database: drizzleAdapter(db, {
        provider: 'pg',
        usePlural: true,
    }),
    basePath: '/api', // Clean API prefix for all Better Auth endpoints
    // Enable organizations plugin
    plugins: [
        organization({
            // You can customize roles, permissions, and schema mapping here
            // See Better Auth docs for advanced options
        }),
        openAPI()
    ],
    // Example: enable email/password auth (customize as needed)
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
        minPasswordLength: 8,
        maxPasswordLength: 128,
    },
    // Add other Better Auth config as needed (social, 2FA, etc.)
});

let _schema: ReturnType<typeof auth.api.generateOpenAPISchema>;
const getSchema = async () => (_schema ??= auth.api.generateOpenAPISchema())

export const OpenAPI = {
    getPaths: (prefix = '/auth/api') =>
        getSchema().then(({ paths }) => {
            const reference: typeof paths = Object.create(null)

            for (const path of Object.keys(paths)) {
                const key = prefix + path
                reference[key] = paths[path]

                for (const method of Object.keys(paths[path])) {
                    const operation = (reference[key] as any)[method]

                    operation.tags = ['Better Auth']
                }
            }

            return reference
        }) as Promise<any>,
    components: getSchema().then(({ components }) => components) as Promise<any>
} as const
