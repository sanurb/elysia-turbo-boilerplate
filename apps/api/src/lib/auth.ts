import { betterAuth } from 'better-auth';
import { admin, bearer, createAuthMiddleware, multiSession, openAPI, organization } from 'better-auth/plugins';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from '../db';
import { accounts, invitations, members, organizations, sessions, users, verifications } from '@/db/auth_schema';

/**
 * Better Auth configuration with Drizzle ORM and organizations plugin.
 * Uses the official Drizzle adapter for full compatibility and performance.
 * - provider: 'pg' for PostgreSQL
 * - usePlural: true since all tables use plural names
 */
export const auth = betterAuth({
    appName: 'API',
    database: drizzleAdapter(db, {
        provider: 'pg',
        usePlural: true,
        schema: {
            users,
            sessions,
            accounts,
            verifications,
            organizations,
            members,
            invitations,
        }
    }),
    baseURL: process.env.BETTER_AUTH_URL,
    basePath: '/api',
    plugins: [
        organization({
            // You can customize roles, permissions, and schema mapping here
            // See Better Auth docs for advanced options
        }),
        bearer(),
        admin(),
        multiSession(),
        openAPI()
    ],
    // Example: enable email/password auth (customize as needed)
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
        minPasswordLength: 8,
        maxPasswordLength: 128,
    },
    trustedOrigins: ['http://localhost:3000', 'http://localhost:4000', '0.0.0.0:3000', '192.168.1.102:3000'],
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
