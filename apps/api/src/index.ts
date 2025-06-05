import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { staticPlugin } from "@elysiajs/static";
import serverTiming from "@elysiajs/server-timing";
import { helmet } from "elysia-helmet";
import prometheusPlugin from "elysia-prometheus";
import { styleText } from "node:util";
import logger from 'logixlysia';
import { env } from "@yolk-oss/elysia-env";

const EnvSchema = t.Object({
    DATABASE_URL: t.String({ minLength: 1, error: "DATABASE_URL is required!" }),
    BETTER_AUTH_SECRET: t.String({ minLength: 1, error: "BETTER_AUTH_SECRET is required!" })
});

const app = new Elysia({
    name: 'api'
})
    .use(cors())
    .use(helmet())
    .use(logger())
    .use(serverTiming())
    .use(swagger({
        exclude: ['/swagger'],
        autoDarkMode: true,
    }))
    .use(
        prometheusPlugin({
            metricsPath: '/metrics',
            staticLabels: { service: 'api' },
            dynamicLabels: {
                userAgent: (ctx) =>
                    ctx.request.headers.get('user-agent') ?? 'unknown'
            }
        })
    )
    .use(
        staticPlugin({
            prefix: ''
        })
    )
    .get('/', () => ({ message: 'Elysia API', version: '1.0.0' }))
    .get('/favicon.ico', () => new Response(null, { status: 204 }))
    .get("/health", () => ({ status: "ok" }))
    .onError(({ code, error, request }) => {    
        // Don't log 404s for favicon or common browser requests
        if (code === 'NOT_FOUND' && (
            request.url.includes('favicon.ico') || 
            request.url.includes('.ico') ||
            request.url.includes('.png') ||
            request.url.includes('.svg') ||
            request.url.includes('devtools')
        )) {
            return new Response(null, { status: 404 });
        }
        
        console.error(`Error ${code} for ${request.method} ${request.url}:`, error);

        return {
            error: true,
            message: error instanceof Error ? error.message : 'Internal server error',
            code,
            path: new URL(request.url).pathname
        };
    })

    // Catch-all route for unmatched paths
    .all('*', ({ request }) => {
        console.log(`Unmatched route: ${request.method} ${request.url}`);
        return new Response(
            JSON.stringify({ 
                error: true, 
                message: `Route not found: ${request.method} ${new URL(request.url).pathname}`,
                code: 'NOT_FOUND'
            }), 
            { 
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            }
        );
    })

    .listen(3000);

console.log(
    styleText('green', `\nServer is running\n`),
    styleText('green', 'API: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}\n`),
    styleText('green', 'Docs: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}/swagger\n`),
    styleText('green', 'Metrics: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}/metrics\n`)
);
