import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import prometheusPlugin from "elysia-prometheus";
import { styleText } from "node:util";
import { OpenAPI } from './lib/auth';
import authController from "./controllers/auth.controller";

const app = new Elysia()
    .use(cors({
        origin: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        credentials: true,
        allowedHeaders: ['Content-Type', 'Authorization']
    }))
    // .use(logger())
    // .use(serverTiming())
    .use(swagger({
        autoDarkMode: true,
        documentation: {
            components: await OpenAPI.components,
            paths: await OpenAPI.getPaths(),
        },
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
    .get('/', () => ({ message: 'Elysia API', version: '1.0.0' }))
    .get('/favicon.ico', () => new Response(null, { status: 204 }))
    .get("/health", () => "OK")
    .use(authController)
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
    // .all('*', ({ request }) => {
    //     console.log(`Unmatched route: ${request.method} ${request.url}`);
    //     return new Response(
    //         JSON.stringify({
    //             error: true,
    //             message: `Route not found: ${request.method} ${new URL(request.url).pathname}`,
    //             code: 'NOT_FOUND'
    //         }),
    //         {
    //             status: 404,
    //             headers: { 'Content-Type': 'application/json' }
    //         }
    //     );
    // })

    .listen({
        hostname: '0.0.0.0',
        port: 3000,
    });

console.log(
    styleText('green', `\nServer is running\n`),
    styleText('green', 'API: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}\n`),
    styleText('green', 'Docs: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}/swagger\n`),
    styleText('green', 'Metrics: '),
    styleText('cyan', `http://${app.server?.hostname}:${app.server?.port}/metrics\n`)
);

export default app;

/** This export is used with '@elysiajs/eden'. */
export type App = typeof app;
