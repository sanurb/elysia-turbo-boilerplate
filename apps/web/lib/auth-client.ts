import { createAuthClient } from "better-auth/react"
import { adminClient, multiSessionClient, organizationClient } from "better-auth/client/plugins"
import { toast } from "sonner"

export const authClient = createAuthClient({
    baseURL: 'http://localhost:3000',
    basePath: '/auth/api',
    plugins: [
        organizationClient(),
        adminClient(),
        multiSessionClient(),
    ],
    fetchOptions: {
        onError(e) {
            if (e.error.status === 429) {
                toast.error("Too many requests. Please try again later.");
            }
        },
    },
})

export const {
    signUp,
    signIn,
    signOut,
    useSession,
    organization,
    useListOrganizations,
    useActiveOrganization,
} = authClient;

authClient.$store.listen("$sessionSignal", async () => { });
