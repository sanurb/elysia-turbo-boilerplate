TITLE: Install Better Auth Library (pnpm)
DESCRIPTION: Installs the Better Auth library using the pnpm package manager. This is the first step to integrate the library into your project.
SOURCE: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/README.md#_snippet_0

LANGUAGE: bash
CODE:
```
pnpm install better-auth
```

----------------------------------------

TITLE: Client-Side Email Sign Up - Better Auth - TypeScript
DESCRIPTION: Demonstrates how to sign up a user using email and password on the client side with `authClient.signUp.email`. It includes parameters for user details like email, password, name, and optional image and callback URL, along with callbacks for request lifecycle.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_1

LANGUAGE: TypeScript
CODE:
```
import { authClient } from "@/lib/auth-client"; //import the auth client // [!code highlight]

const { data, error } = await authClient.signUp.email({
        email, // user email address
        password, // user password -> min 8 characters by default
        name, // user display name
        image, // User image URL (optional)
        callbackURL: "/dashboard" // A URL to redirect to after the user verifies their email (optional)
    }, {
        onRequest: (ctx) => {
            //show loading
        },
        onSuccess: (ctx) => {
            //redirect to the dashboard or sign in page
        },
        onError: (ctx) => {
            // display the error message
            alert(ctx.error.message);
        },
});
```

----------------------------------------

TITLE: Implement Better Auth Global Middleware (TypeScript)
DESCRIPTION: Example of a Nuxt global middleware that uses `authClient.useSession` with `useFetch` to check if a user has a session and redirects them if they try to access a protected route like '/dashboard' without one.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/nuxt.mdx#_snippet_6

LANGUAGE: ts
CODE:
```
import { authClient } from "~/lib/auth-client";
export default defineNuxtRouteMiddleware(async (to, from) => {
	const { data: session } = await authClient.useSession(useFetch); 
	if (!session.value) {
		if (to.path === "/dashboard") {
			return navigateTo("/");
		}
	}
});
```

----------------------------------------

TITLE: Enabling Cross-Subdomain Cookies in Better Auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to configure Better Auth to share session cookies across subdomains. It involves setting `crossSubDomainCookies` with an enabled flag and a leading-period domain, along with `defaultCookieAttributes` like `sameSite: "none"` and `partitioned: true`. Additionally, `trustedOrigins` must be configured to mitigate CSRF risks associated with `sameSite: "none"`.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/cookies.mdx#_snippet_2

LANGUAGE: typescript
CODE:
```
import { betterAuth } from "better-auth"

export const auth = betterAuth({
    advanced: {
        crossSubDomainCookies: {
            enabled: true,
            domain: ".example.com" // Domain with a leading period
        },
        defaultCookieAttributes: {
            secure: true,
            httpOnly: true,
            sameSite: "none",  // Allows CORS-based cookie sharing across subdomains
            partitioned: true // New browser standards will mandate this for foreign cookies
        }
    },
    trustedOrigins: [
        'https://example.com',
        'https://app1.example.com',
        'https://app2.example.com'
    ]
})
```

----------------------------------------

TITLE: Getting Session on Server with `auth.api.getSession` (TSX)
DESCRIPTION: Demonstrates how to retrieve a session on the server side (e.g., Next.js server components) using `auth.api.getSession`. This method allows passing request headers to access cookies, which `authClient.getSession` cannot directly do in a server environment.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/faq.mdx#_snippet_2

LANGUAGE: TSX
CODE:
```
import { auth } from "./auth";
import { headers } from "next/headers";

const session = await auth.api.getSession({
    headers: await headers()
})
```

----------------------------------------

TITLE: Register Passkey with better-auth Client (TypeScript)
DESCRIPTION: Calls the `addPasskey` function on the `passkey` plugin instance available via `authClient`. This initiates the passkey registration process for the currently authenticated user using default settings, allowing both platform and cross-platform authenticators.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/passkey.mdx#_snippet_4

LANGUAGE: ts
CODE:
```
// Default behavior allows both platform and cross-platform passkeys
const { data, error } = await authClient.passkey.addPasskey();
```

----------------------------------------

TITLE: Adding Additional Fields to User Object (TypeScript)
DESCRIPTION: This example shows how to extend the user object with additional fields, such as 'role', within the `betterAuth` configuration. These custom fields are then properly inferred and available on the `Session` type.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/typescript.mdx#_snippet_4

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import Database from "better-sqlite3"

export const auth = betterAuth({
    database: new Database("database.db"),
    user: {
       additionalFields: {
          role: {
              type: "string"
            } 
        }
    }
   
})

type Session = typeof auth.$Infer.Session
```

----------------------------------------

TITLE: Configure Send OTP Function in Better Auth (TypeScript)
DESCRIPTION: Demonstrates how to configure the `sendOTP` function within the `otpOptions` of the `twoFactor` plugin when initializing Better Auth. This function is responsible for sending the One-Time Password (OTP) to the user via email, phone, or other configured methods, integrating with your application's communication layer.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/2fa.mdx#_snippet_13

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth"
import { twoFactor } from "better-auth/plugins"

export const auth = betterAuth({
    plugins: [
        twoFactor({
          	otpOptions: {
				async sendOTP({ user, otp }, request) {
                    // send otp to user
				},
			},
        })
    ]
})
```

----------------------------------------

TITLE: Finding Multiple Records in Better Auth (TypeScript)
DESCRIPTION: This method retrieves multiple records from the database. It takes the `model` (table name), a `where` clause for filtering, and optional parameters for `limit`, `sortBy`, and `offset` to control pagination and ordering. The method returns an array of data objects matching the query.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/create-a-db-adapter.mdx#_snippet_10

LANGUAGE: TypeScript
CODE:
```
findMany: async ({ model, where, limit, sortBy, offset }) => {
  // Example of finding multiple records in the database.
  return await db
    .select()
    .from(model)
    .where(where)
    .limit(limit)
    .offset(offset)
    .orderBy(sortBy);
};
```

----------------------------------------

TITLE: Creating a Basic Server-Side Better Auth Plugin (TypeScript)
DESCRIPTION: This snippet illustrates the basic structure for creating a server-side Better Auth plugin. It defines a function that returns an object satisfying the `BetterAuthPlugin` interface, with `id` being the only required property. It's recommended to make the plugin a function to allow passing options.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/plugins.mdx#_snippet_2

LANGUAGE: TypeScript
CODE:
```
import type { BetterAuthPlugin } from "better-auth";

export const myPlugin = ()=>{
    return {
        id: "my-plugin",
    } satisfies BetterAuthPlugin
}
```

----------------------------------------

TITLE: Create Better Auth Instance (TypeScript)
DESCRIPTION: Imports the `betterAuth` function and creates an authentication instance in a TypeScript file (e.g., `auth.ts`). This instance should be exported as `auth` or as a default export for use throughout your application.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/installation.mdx#_snippet_3

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth";

export const auth = betterAuth({
    //...
})
```

----------------------------------------

TITLE: Add Passkey Plugin to better-auth Config (TypeScript)
DESCRIPTION: Imports the `passkey` plugin from `better-auth/plugins/passkey` and adds it to the `plugins` array when initializing the `betterAuth` instance. This enables passkey authentication functionality in the server-side authentication setup.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/passkey.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { passkey } from "better-auth/plugins/passkey" // [!code highlight]

export const auth = betterAuth({
    plugins: [ // [!code highlight]
        passkey(), // [!code highlight]
    ], // [!code highlight]
})
```

----------------------------------------

TITLE: Restricting Organization Creation (auth.ts)
DESCRIPTION: Configure the organization plugin on the server to restrict organization creation based on user properties, such as checking a user's subscription plan.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/organization.mdx#_snippet_5

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { organization } from "better-auth/plugins"

const auth = betterAuth({
    //...
    plugins: [
        organization({
            allowUserToCreateOrganization: async (user) => { // [!code highlight]
                const subscription = await getSubscription(user.id) // [!code highlight]
                return subscription.plan === "pro" // [!code highlight]
            } // [!code highlight]
        })
    ]
})
```

----------------------------------------

TITLE: Validating JWT with Local JWKS using Jose (TypeScript)
DESCRIPTION: This TypeScript function illustrates how to verify a JWT using the `jose` library against a locally stored JSON Web Key Set (JWKS). It uses `createLocalJWKSet` with a predefined JWKS object and `jwtVerify` for validation, configuring the issuer and audience. This approach is suitable for scenarios where the JWKS can be cached or is static.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/jwt.mdx#_snippet_8

LANGUAGE: ts
CODE:
```
import { jwtVerify, createLocalJWKSet } from 'jose'


async function validateToken(token: string) {
  try {
    /**
     * This is the JWKS that you get from the /api/auth/
     * jwks endpoint
     */
    const storedJWKS = {
      keys: [{
        //...
      }]
    };
    const JWKS = createLocalJWKSet({
      keys: storedJWKS.data?.keys!,
    })
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'http://localhost:3000', // Should match your JWT issuer, which is the BASE_URL
      audience: 'http://localhost:3000', // Should match your JWT audience, which is the BASE_URL by default
    })
    return payload
  } catch (error) {
    console.error('Token validation failed:', error)
    throw error
  }
}

// Usage example
const token = 'your.jwt.token' // this is the token you get from the /api/auth/token endpoint
const payload = await validateToken(token)
```

----------------------------------------

TITLE: Revoke All User Sessions - authClient.admin - TypeScript
DESCRIPTION: Revokes all active sessions for a specific user using the `authClient.admin.revokeUserSessions` method. Requires the user's ID.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/admin.mdx#_snippet_14

LANGUAGE: typescript
CODE:
```
const revokedSessions = await authClient.admin.revokeUserSessions({
  userId: "user_id_here",
});
```

----------------------------------------

TITLE: Social Sign-In with ID Token (Google) in React Native
DESCRIPTION: This example illustrates how to perform social sign-in by providing an ID token obtained from a mobile device's authentication flow. The `authClient.signIn.social` method is used with the `idToken` option, which includes the token and an optional nonce, allowing for server-side verification. Only Google, Apple, and Facebook are supported for this method.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/expo.mdx#_snippet_15

LANGUAGE: tsx
CODE:
```
import { Button } from "react-native";

export default function App() {
    const handleLogin = async () => {
        await authClient.signIn.social({
            provider: "google", // only google, apple and facebook are supported for idToken sign-in
            idToken: {
                token: "...", // ID token from provider
                nonce: "..." // nonce from provider (optional)
            },
            callbackURL: "/dashboard" // this will be converted to a deep link (eg. `myapp://dashboard`) on native
        })
    };
    return <Button title="Login with Google" onPress={handleLogin} />;
}
```

----------------------------------------

TITLE: Configuring Better Auth with Plugins (TypeScript)
DESCRIPTION: This snippet demonstrates how to initialize `betterAuth` with a PostgreSQL database connection and integrate various optional plugins like Admin, Two Factor, Phone Number, and Username. It also shows configuration for email/password authentication and social providers like GitHub.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/clerk-migration-guide.mdx#_snippet_4

LANGUAGE: typescript
CODE:
```
import { Pool } from "pg";
import { betterAuth } from "better-auth";
import { admin, twoFactor, phoneNumber, username } from "better-auth/plugins";

export const auth = betterAuth({
    database: new Pool({
        connectionString: process.env.DATABASE_URL
    }),
    emailAndPassword: {
        enabled: true,
    },
    socialProviders: {
        github: {
            clientId: process.env.GITHUB_CLIENT_ID!,
            clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        }
    },
    plugins: [admin(), twoFactor(), phoneNumber(), username()],
})
```

----------------------------------------

TITLE: Installing PostgreSQL Client (npm)
DESCRIPTION: This command installs the 'pg' package, which is a PostgreSQL client library for Node.js. It is required to establish a connection to your PostgreSQL database from your application.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/supabase-migration-guide.mdx#_snippet_0

LANGUAGE: bash
CODE:
```
npm install pg
```

----------------------------------------

TITLE: Using useSession Hook with React Client
DESCRIPTION: Demonstrates how to initialize the Better Auth React client and use the `useSession` hook to access reactive session data, including loading state, errors, and a refetch function. It shows how to destructure the `data`, `isPending`, `error`, and `refetch` properties from the hook's return value.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/client.mdx#_snippet_3

LANGUAGE: tsx
CODE:
```
//make sure you're using the react client
import { createAuthClient } from "better-auth/react"
const { useSession } = createAuthClient() // [!code highlight]

export function User() {
    const {
        data: session,
        isPending, //loading state
        error, //error object 
        refetch //refetch the session
    } = useSession()
    return (
        //...
    )
}
```

----------------------------------------

TITLE: Signing Out (TypeScript)
DESCRIPTION: Shows the basic usage of the `authClient.signOut()` function to log out the current user.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_7

LANGUAGE: ts
CODE:
```
await authClient.signOut();
```

----------------------------------------

TITLE: Implementing Database Lifecycle Hooks in better-auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to configure database lifecycle hooks for core operations like user creation and update in `better-auth`. It shows how to define `before` and `after` hooks to modify data or perform actions before and after database operations, providing flexibility for custom logic and data manipulation.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/options.mdx#_snippet_18

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
export const auth = betterAuth({
	databaseHooks: {
		user: {
			create: {
				before: async (user) => {
					// Modify user data before creation
					return { data: { ...user, customField: "value" } };
				},
				after: async (user) => {
					// Perform actions after user creation
				}
			},
			update: {
				before: async (userData) => {
					// Modify user data before update
					return { data: { ...userData, updatedAt: new Date() } };
				},
				after: async (user) => {
					// Perform actions after user update
				}
			}
		},
		session: {
			// Session hooks
		},
		account: {
			// Account hooks
		},
		verification: {
			// Verification hooks
		}
	},
})
```

----------------------------------------

TITLE: Accessing Session with useSession Hook (React/TSX)
DESCRIPTION: Shows how to use the `authClient.useSession()` hook within a React functional component to access session data, loading state (`isPending`), errors, and a refetch function. This hook provides reactive session updates.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_9

LANGUAGE: tsx
CODE:
```
import { authClient } from "@/lib/auth-client" // import the auth client // [!code highlight] 

export function User(){

    const { // [!code highlight]
        data: session, // [!code highlight]
        isPending, //loading state // [!code highlight]
        error, //error object // [!code highlight]
        refetch //refetch the session
    } = authClient.useSession() // [!code highlight]

    return (
        //...
    )
}
```

----------------------------------------

TITLE: Using Next.js 'use cache' Directive (TypeScript)
DESCRIPTION: Demonstrates how to use the Next.js `use cache` directive within a server function to cache the result of fetching users via the Better Auth API. This directive instructs Next.js to cache the function's output for subsequent calls. Requires Next.js v15+.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/optimizing-for-performance.mdx#_snippet_1

LANGUAGE: ts
CODE:
```
export async function getUsers() {
    'use cache' // [!code highlight]
    const { users } = await auth.api.listUsers();
    return users
}
```

----------------------------------------

TITLE: Resetting User Password with Email OTP
DESCRIPTION: This snippet demonstrates how to reset a user's password using `authClient.emailOtp.resetPassword`. It requires the user's `email`, the `otp` received, and the `new password`. This method allows users to regain access to their account by setting a new password after successful OTP verification.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/email-otp.mdx#_snippet_5

LANGUAGE: ts
CODE:
```
const { data, error } = await authClient.emailOtp.resetPassword({
    email: "user-email@email.com",
    otp: "123456",
    password: "password"
})
```

----------------------------------------

TITLE: Initializing Better Auth Project with CLI (Bash)
DESCRIPTION: This command initializes Better Auth within a project, setting up the necessary configurations. It offers various options to customize the initialization, including application name, framework (currently Next.js), desired plugins, database (currently SQLite), and package manager.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/cli.mdx#_snippet_2

LANGUAGE: bash
CODE:
```
npx @better-auth/cli@latest init
```

----------------------------------------

TITLE: Hashing Password for Server-Side Update (TypeScript)
DESCRIPTION: This server-side snippet shows how to hash a new password using the `better-auth` context. It retrieves the authentication context and then uses `ctx.password.hash` to securely hash the provided password before it can be stored or updated.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_12

LANGUAGE: typescript
CODE:
```
const ctx = await auth.$context;
const hash = await ctx.password.hash("your-new-password");
```

----------------------------------------

TITLE: Signing In a User with Email and Password using Better Auth Client (TypeScript)
DESCRIPTION: This snippet shows how to authenticate an existing user using the `authClient.signIn.email` function. It requires the user's email and password, and optionally accepts a `rememberMe` flag (defaulting to true) to control session persistence and a `callbackURL` for redirection after successful sign-in.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_2

LANGUAGE: TypeScript
CODE:
```
const { data, error } = await authClient.signIn.email({
  email: "test@example.com",
  password: "password1234",
});
```

----------------------------------------

TITLE: Client-Side Email Sign In - Better Auth - TypeScript
DESCRIPTION: Provides an example of signing in a user using email and password on the client side via `authClient.signIn.email`. It shows parameters like email, password, an optional callback URL, and the `rememberMe` option to control session persistence.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_3

LANGUAGE: TypeScript
CODE:
```
const { data, error } = await authClient.signIn.email({
        /**
         * The user email
         */
        email,
        /**
         * The user password
         */
        password,
        /**
         * A URL to redirect to after the user verifies their email (optional)
         */
        callbackURL: "/dashboard",
        /**
         * remember the user session after the browser is closed. 
         * @default true
         */
        rememberMe: false
}, {
    //callbacks
})
```

----------------------------------------

TITLE: Server-Side Email Sign In - Better Auth - TypeScript
DESCRIPTION: Shows how to perform email and password sign-in on the server side using `auth.api.signInEmail`. It includes passing credentials in the `body` and optionally setting `asResponse: true` to receive a response object directly.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_4

LANGUAGE: TypeScript
CODE:
```
import { auth } from "./auth"; // path to your Better Auth server instance

const response = await auth.api.signInEmail({
    body: {
        email,
        password
    },
    asResponse: true // returns a response object instead of data
});
```

----------------------------------------

TITLE: Configuring Coinbase as a Generic OAuth Provider in Better Auth
DESCRIPTION: This snippet illustrates how to configure Coinbase as an OAuth2 provider using the `genericOAuth` plugin. It sets the `providerId` to 'coinbase', uses environment variables for `clientId` and `clientSecret`, and defines the `authorizationUrl`, `tokenUrl`, and necessary `scopes` for Coinbase's OAuth API.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/other-social-providers.mdx#_snippet_6

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

export const auth = betterAuth({
  // ... other config options
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "coinbase",
          clientId: process.env.COINBASE_CLIENT_ID as string,
          clientSecret: process.env.COINBASE_CLIENT_SECRET as string,
          authorizationUrl: "https://www.coinbase.com/oauth/authorize",
          tokenUrl: "https://api.coinbase.com/oauth/token",
          scopes: ["wallet:user:read"], // and more...
        },
      ],
    }),
  ],
});
```

----------------------------------------

TITLE: Configuring Email Verification with Better Auth (TypeScript)
DESCRIPTION: This snippet illustrates how to configure email verification by providing a `sendVerificationEmail` function within the `emailVerification` option of `betterAuth`. This asynchronous function is responsible for sending a verification email to the user, including a unique URL with a token for completing the verification process.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_5

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { sendEmail } from "./email"; // your email sending function

export const auth = betterAuth({
  emailVerification: {
    sendVerificationEmail: async ( { user, url, token }, request) => {
      await sendEmail({
        to: user.email,
        subject: "Verify your email address",
        text: `Click the link to verify your email: ${url}`,
      });
    },
  },
});
```

----------------------------------------

TITLE: Configuring Email and Password Authentication (TypeScript)
DESCRIPTION: Sets up email and password authentication, allowing customization of features like sign-up, email verification requirement, password length constraints, auto sign-in, reset password functionality, and custom hashing/verification.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/options.mdx#_snippet_9

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
export const auth = betterAuth({
	emailAndPassword: {
		enabled: true,
		disableSignUp: false,
		requireEmailVerification: true,
		minPasswordLength: 8,
		maxPasswordLength: 128,
		autoSignIn: true,
		sendResetPassword: async ({ user, url, token }) => {
			// Send reset password email
		},
		resetPasswordTokenExpiresIn: 3600, // 1 hour
		password: {
			hash: async (password) => {
				// Custom password hashing
				return hashedPassword;
			},
			verify: async ({ hash, password }) => {
				// Custom password verification
				return isValid;
			}
		}
	},
})
```

----------------------------------------

TITLE: Generating Better Auth Schema (CLI)
DESCRIPTION: This command generates the necessary database schema for Better Auth. It supports various ORMs like Prisma and Drizzle, generating ORM-specific schema files, or an SQL file for the built-in Kysely adapter. Options include `--output` for specifying the save location, `--config` for the configuration file path, and `--y` to skip prompts.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/changelogs/1.0.mdx#_snippet_0

LANGUAGE: bash
CODE:
```
npx @better-auth/cli@latest generate
```

----------------------------------------

TITLE: Signing In User with Email OTP
DESCRIPTION: This snippet demonstrates how to authenticate a user using an email OTP via `authClient.signIn.emailOtp`. It takes the user's `email` and the provided `otp` as parameters. If the user is not registered, they will be automatically signed up unless `disableSignUp` is set to `true` in the plugin options.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/email-otp.mdx#_snippet_3

LANGUAGE: ts
CODE:
```
const { data, error } = await authClient.signIn.emailOtp({
    email: "user-email@email.com",
    otp: "123456"
})
```

----------------------------------------

TITLE: Getting Session in Nuxt (TypeScript)
DESCRIPTION: Shows how to get the server-side session within a Nuxt server API route using `defineEventHandler`. The session is retrieved by passing `event.headers` to `auth.api.getSession`. Requires importing the `auth` instance.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_20

LANGUAGE: TypeScript
CODE:
```
import { auth } from "~/utils/auth";

export default defineEventHandler(async (event) => {
    const session = await auth.api.getSession({
        headers: event.headers,
    })
});
```

----------------------------------------

TITLE: Defining Static Subscription Plans (TypeScript)
DESCRIPTION: This configuration defines subscription plans statically within the application. Each plan includes a name, Stripe price IDs for monthly and optional annual billing, and custom limits for resources like projects and storage, along with an optional free trial period.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/stripe.mdx#_snippet_7

LANGUAGE: TypeScript
CODE:
```
subscription: {
    enabled: true,
    plans: [
        {
            name: "basic", // the name of the plan, it'll be automatically lower cased when stored in the database
            priceId: "price_1234567890", // the price ID from stripe
            annualDiscountPriceId: "price_1234567890", // (optional) the price ID for annual billing with a discount
            limits: {
                projects: 5,
                storage: 10
            }
        },
        {
            name: "pro",
            priceId: "price_0987654321",
            limits: {
                projects: 20,
                storage: 50
            },
            freeTrial: {
                days: 14,
            }
        }
    ]
}
```

----------------------------------------

TITLE: Obtaining and Storing Bearer Token on Sign-In (TypeScript)
DESCRIPTION: This code shows how to obtain a session token after a successful email sign-in using `authClient.signIn.email`. It extracts the `set-auth-token` from the response headers within the `onSuccess` callback and securely stores it in `localStorage` for subsequent authenticated requests.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/bearer.mdx#_snippet_1

LANGUAGE: TypeScript
CODE:
```
const { data } = await authClient.signIn.email({
    email: "user@example.com",
    password: "securepassword"
}, {
  onSuccess: (ctx)=>{
    const authToken = ctx.response.headers.get("set-auth-token") // get the token from the response headers
    // Store the token securely (e.g., in localStorage)
    localStorage.setItem("bearer_token", authToken);
  }
});
```

----------------------------------------

TITLE: Verifying User Email with OTP
DESCRIPTION: This snippet shows how to verify a user's email address using `authClient.emailOtp.verifyEmail`. It requires the user's `email` and the `otp` received. This method confirms the ownership of the email address.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/email-otp.mdx#_snippet_4

LANGUAGE: ts
CODE:
```
const { data, error } = await authClient.emailOtp.verifyEmail({
    email: "user-email@email.com",
    otp: "123456"
})
```

----------------------------------------

TITLE: Configuring Send Reset Password Function in better-auth (TypeScript)
DESCRIPTION: This configuration snippet provides the `sendResetPassword` function to the `emailAndPassword` authenticator. It defines how the reset password email is sent, including the user's email, the reset URL, and the token, using a custom `sendEmail` utility.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_9

LANGUAGE: typescript
CODE:
```
import { betterAuth } from "better-auth";
import { sendEmail } from "./email"; // your email sending function

export const auth = betterAuth({
  emailAndPassword: {
    enabled: true,
    sendResetPassword: async ({user, url, token}, request) => {
      await sendEmail({
        to: user.email,
        subject: "Reset your password",
        text: `Click the link to reset your password: ${url}`,
      });
    },
  },
});
```

----------------------------------------

TITLE: Displaying User Session Status (TSX)
DESCRIPTION: This TSX component, `IndexPopup`, demonstrates how to use `authClient.useSession()` to fetch and display the user's session status. It conditionally renders 'Loading...', an error message, or the signed-in user's name based on the session data, `isPending`, and `error` states.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/browser-extension-guide.mdx#_snippet_6

LANGUAGE: tsx
CODE:
```
import { authClient } from "./auth/auth-client"


function IndexPopup() {
    const {data, isPending, error} = authClient.useSession();
    if(isPending){
        return <>Loading...</>
    }
    if(error){
        return <>Error: {error.message}</>
    }
    if(data){
        return <>Signed in as {data.user.name}</>
    }
}

export default IndexPopup;
```

----------------------------------------

TITLE: Configuring Default Cookie Attributes for Better Auth (TypeScript)
DESCRIPTION: This snippet shows how to globally adjust default cookie attributes for Better Auth, such as 'sameSite', 'secure', and 'partitioned', within the 'createAuth' configuration. Setting 'sameSite' to 'none' and 'secure' to 'true' is necessary for cross-domain cookies, and 'partitioned' addresses new browser standards for foreign cookies.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/hono.mdx#_snippet_5

LANGUAGE: TypeScript
CODE:
```
export const auth = createAuth({
  advanced: {
    defaultCookieAttributes: {
      sameSite: "none",
      secure: true,
      partitioned: true // New browser standards will mandate this for foreign cookies
    }
  }
})
```

----------------------------------------

TITLE: Pre-fetching Session for SSR (TypeScript)
DESCRIPTION: Shows how to pre-fetch the user session on the server side for use in SSR frameworks. It retrieves the session using the Better Auth API, passing the request headers. This session data can then be passed to the client as initial state. Requires access to request headers.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/optimizing-for-performance.mdx#_snippet_5

LANGUAGE: ts
CODE:
```
const session = await auth.api.getSession({
  headers: await headers(),
});
//then pass the session to the client
```

----------------------------------------

TITLE: Validating JWT with Remote JWKS using Jose (TypeScript)
DESCRIPTION: This TypeScript function demonstrates how to verify a JWT using the `jose` library by fetching the JSON Web Key Set (JWKS) from a remote endpoint. It utilizes `createRemoteJWKSet` to retrieve the public keys and `jwtVerify` for validation, including configuration for issuer and audience. This method allows for dynamic key updates.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/jwt.mdx#_snippet_7

LANGUAGE: ts
CODE:
```
import { jwtVerify, createRemoteJWKSet } from 'jose'

async function validateToken(token: string) {
  try {
    const JWKS = createRemoteJWKSet(
      new URL('http://localhost:3000/api/auth/jwks')
    )
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'http://localhost:3000', // Should match your JWT issuer, which is the BASE_URL
      audience: 'http://localhost:3000', // Should match your JWT audience, which is the BASE_URL by default
    })
    return payload
  } catch (error) {
    console.error('Token validation failed:', error)
    throw error
  }
}

// Usage example
const token = 'your.jwt.token' // this is the token you get from the /api/auth/token endpoint
const payload = await validateToken(token)
```

----------------------------------------

TITLE: Mounting Better Auth Handler for Next.js App Router
DESCRIPTION: This snippet demonstrates how to create an API route handler for Better Auth using the Next.js App Router. It imports the 'auth' instance and 'toNextJsHandler' to expose 'GET' and 'POST' methods, allowing Better Auth to handle authentication requests at '/api/auth/[...all]'.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/next.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { auth } from "@/lib/auth";
import { toNextJsHandler } from "better-auth/next-js";

export const { GET, POST } = toNextJsHandler(auth.handler);
```

----------------------------------------

TITLE: Using useSession Hook with Svelte Client
DESCRIPTION: Demonstrates how to use the `useSession` hook in a Svelte component. It shows how to reactively display user information (name, email) if a session exists, or provide a 'Continue with GitHub' button for social sign-in, along with a sign-out button.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/client.mdx#_snippet_5

LANGUAGE: svelte
CODE:
```
<script lang="ts">
import { client } from "$lib/client";
const session = client.useSession();
</script>

<div
    style="display: flex; flex-direction: column; gap: 10px; border-radius: 10px; border: 1px solid #4B453F; padding: 20px; margin-top: 10px;"
>
    <div>
    {#if $session}
        <div>
        <p>
            {$session?.data?.user.name}
        </p>
        <p>
            {$session?.data?.user.email}
        </p>
        <button
            on:click={async () => {
            await authClient.signOut();
            }}
        >
            Signout
        </button>
        </div>
    {:else}
        <button
        on:click={async () => {
            await authClient.signIn.social({
            provider: "github",
            });
        }}
        >
        Continue with GitHub
        </button>
    {/if}
    </div>
</div>
```

----------------------------------------

TITLE: Configuring Database for Better Auth (TypeScript)
DESCRIPTION: Sets up the database connection for Better Auth, specifying the dialect and type. Better Auth supports PostgreSQL, MySQL, and SQLite.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/options.mdx#_snippet_6

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
export const auth = betterAuth({
	database: {
		dialect: "postgres",
		type: "postgres",
		casing: "camel"
	},
})
```

----------------------------------------

TITLE: Configuring Server-Side Plugins with Better Auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to configure server-side plugins in Better Auth. Plugins are added to the `plugins` array within the `betterAuth` configuration object. This allows extending the core authentication functionalities on the server.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/plugins.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";

export const auth = betterAuth({
    plugins: [
        // Add your plugins here
    ]
});
```

----------------------------------------

TITLE: Throwing APIError in User Creation Before Hook - Better Auth - TypeScript
DESCRIPTION: This example shows how to use the APIError class within a 'before' database hook to halt the operation and return a specific error response if a custom condition (user not agreeing to terms) is not met.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/database.mdx#_snippet_12

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";

export const auth = betterAuth({
  databaseHooks: {
    user: {
      create: {
        before: async (user, ctx) => {
          if (user.isAgreedToTerms === false) {
            // Your special condition.
            // Send the API error.
            throw new APIError("BAD_REQUEST", {
              message: "User must agree to the TOS before signing up.",
            });
          }
          return {
            data: user,
          };
        },
      },
    },
  },
});
```

----------------------------------------

TITLE: Initializing a Basic Better Auth Client Plugin (TypeScript)
DESCRIPTION: This snippet demonstrates the basic structure for creating a Better Auth client plugin. It defines a simple plugin with a unique `id`, serving as the foundation for client-side interactions and endpoint inference.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/plugins.mdx#_snippet_14

LANGUAGE: TypeScript
CODE:
```
import type { BetterAuthClientPlugin } from "better-auth";

export const myPluginClient = ()=>{
    return {
        id: "my-plugin",
    } satisfies BetterAuthClientPlugin
}
```

----------------------------------------

TITLE: Forcing Secure Cookies in Better Auth (TypeScript)
DESCRIPTION: This configuration forces Better Auth to always set the `Secure` attribute on all cookies, regardless of the server's production mode. By setting `useSecureCookies` to `true` within the `advanced` options, it ensures that cookies are only sent over HTTPS connections, enhancing security.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/cookies.mdx#_snippet_3

LANGUAGE: typescript
CODE:
```
import { betterAuth } from "better-auth"

export const auth = betterAuth({
    advanced: {
        useSecureCookies: true
    }
})
```

----------------------------------------

TITLE: Accessing Session Reactively with authClient (TypeScript)
DESCRIPTION: This snippet shows how to use the `useSession` action from `authClient` to reactively access the current session data. This approach is suitable for frameworks or contexts where reactive data fetching and updates are preferred.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/session-management.mdx#_snippet_5

LANGUAGE: TypeScript
CODE:
```
import { authClient } from "@/lib/client"

const { data: session } = authClient.useSession()
```

----------------------------------------

TITLE: Initiating OAuth Sign-In with better-auth Client (TypeScript)
DESCRIPTION: This snippet shows how to programmatically initiate an OAuth sign-in flow using the `authClient.signIn.oauth2` method. It requires a `providerId` to specify which OAuth provider to use and a `callbackURL` where the user will be redirected after successful authentication. This is the entry point for users to log in via an OAuth provider.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/generic-oauth.mdx#_snippet_2

LANGUAGE: ts
CODE:
```
const response = await authClient.signIn.oauth2({
  providerId: "provider-id",
  callbackURL: "/dashboard" // the path to redirect to after the user is authenticated
});
```

----------------------------------------

TITLE: Customize Organization Schema - TypeScript
DESCRIPTION: This snippet shows how to use the `schema` option within the `organization` plugin configuration to map default table and field names to custom names, such as mapping the 'organization' table to 'organizations' and the 'name' field to 'title'. This allows integration with existing database schemas.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/organization.mdx#_snippet_51

LANGUAGE: TypeScript
CODE:
```
const auth = betterAuth({
  plugins: [organization({
    schema: {
      organization: {
        modelName: "organizations",  //map the organization table to organizations
        fields: {
          name: "title" //map the name field to title
        }
      }
    }
  })]
})
```

----------------------------------------

TITLE: Configuring Client-Side Plugins with Better Auth (TypeScript)
DESCRIPTION: This snippet shows how to add client-side plugins using the `createAuthClient` function from `better-auth/client`. Client plugins typically provide frontend interfaces to interact with server plugins, and most functionalities require both server and client components.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/plugins.mdx#_snippet_1

LANGUAGE: TypeScript
CODE:
```
import { createAuthClient } from "better-auth/client";

const authClient =  createAuthClient({
    plugins: [
        // Add your client plugins here
    ]
});
```

----------------------------------------

TITLE: Customizing Stripe Customer Creation (TypeScript)
DESCRIPTION: This snippet demonstrates how to customize the Stripe customer creation process during user sign-up. It shows how to execute custom logic after a customer is created and how to modify the parameters sent to Stripe for customer creation, such as adding metadata.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/stripe.mdx#_snippet_6

LANGUAGE: TypeScript
CODE:
```
stripe({
    // ... other options
    createCustomerOnSignUp: true,
    onCustomerCreate: async ({ customer, stripeCustomer, user }, request) => {
        // Do something with the newly created customer
        console.log(`Customer ${customer.id} created for user ${user.id}`);
    },
    getCustomerCreateParams: async ({ user, session }, request) => {
        // Customize the Stripe customer creation parameters
        return {
            metadata: {
                referralSource: user.metadata?.referralSource
            }
        };
    }
})
```

----------------------------------------

TITLE: Implementing User Sign Up with Better Auth Client (Remix React) - TypeScript
DESCRIPTION: This example demonstrates a Remix React component for user sign-up. It utilizes the client-side 'authClient' to handle email-based registration. The component manages user input for name, email, and password, and includes callback functions ('onRequest', 'onSuccess', 'onError') to manage UI states and handle the outcome of the sign-up attempt.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/remix.mdx#_snippet_3

LANGUAGE: tsx
CODE:
```
import { Form } from "@remix-run/react"
import { useState } from "react"
import { authClient } from "~/lib/auth.client"

export default function SignUp() {
  const [email, setEmail] = useState("")
  const [name, setName] = useState("")
  const [password, setPassword] = useState("")

  const signUp = async () => {
    await authClient.signUp.email(
      {
        email,
        password,
        name,
      },
      {
        onRequest: (ctx) => {
          // show loading state
        },
        onSuccess: (ctx) => {
          // redirect to home
        },
        onError: (ctx) => {
          alert(ctx.error)
        },
      },
    )
  }

  return (
    <div>
      <h2>
        Sign Up
      </h2>
      <Form
        onSubmit={signUp}
      >
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name"
        />
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        <button
          type="submit"
        >
          Sign Up
        </button>
      </Form>
    </div>
  )
}
```

----------------------------------------

TITLE: Configuring Trusted Origins for CSRF Protection
DESCRIPTION: This example demonstrates how to define a list of trusted origins in the trustedOrigins configuration option. By explicitly listing allowed domains like "https://example.com" or "http://localhost:3000", Better Auth can effectively prevent CSRF attacks and open redirects by blocking requests from any unlisted sources.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/security.mdx#_snippet_1

LANGUAGE: typescript
CODE:
```
{
  trustedOrigins: [
    "https://example.com",
    "https://app.example.com",
    "http://localhost:3000"
  ]
}
```

----------------------------------------

TITLE: Fetching Server-Side Session Data with Better Auth in TypeScript
DESCRIPTION: This snippet demonstrates how to retrieve session data on the server using the `auth` instance from Better Auth within a Next.js server action. It imports `auth` from `~/server/auth` and `headers` from `next/headers` to pass the request headers for session validation. The `protectedAction` function asynchronously fetches the session, which can then be used for server-side logic.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/next-auth-migration-guide.mdx#_snippet_7

LANGUAGE: TypeScript
CODE:
```
"use server";

import { auth } from "~/server/auth";
import { headers } from "next/headers";

export const protectedAction = async () => {
    const session = await auth.api.getSession({
        headers: await headers(),
    });
};
```

----------------------------------------

TITLE: Revoking All Other Sessions with authClient (TypeScript)
DESCRIPTION: This snippet shows how to revoke all active sessions for the current user, except for the session from which the call is made. The `revokeOtherSessions` function is useful for security, allowing a user to log out of all other devices.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/session-management.mdx#_snippet_8

LANGUAGE: TypeScript
CODE:
```
await authClient.revokeOtherSessions()
```

----------------------------------------

TITLE: Making Authenticated Requests to Server in TypeScript
DESCRIPTION: This function illustrates how to make authenticated requests to a server by manually retrieving the session cookie using `authClient.getCookie()`. The retrieved cookie is then added to the `Cookie` header of the HTTP request, ensuring that the server can authenticate the user's session.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/expo.mdx#_snippet_17

LANGUAGE: tsx
CODE:
```
import { authClient } from "@/lib/auth-client";

const makeAuthenticatedRequest = async () => {
  const cookies = authClient.getCookie();
  const headers = {
    "Cookie": cookies
  };
  const response = await fetch("http://localhost:8081/api/secure-endpoint", { headers });
  const data = await response.json();
  return data;
};
```

----------------------------------------

TITLE: Enforcing Email Domain Restriction with Better Auth Before Hook (TypeScript)
DESCRIPTION: This 'before' hook prevents user sign-ups if their email address does not end with '@example.com'. It uses `ctx.path` to target the `/sign-up/email` endpoint and `ctx.body.email` for validation, throwing an `APIError` for invalid emails.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/hooks.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { createAuthMiddleware, APIError } from "better-auth/api";

export const auth = betterAuth({
    hooks: {
        before: createAuthMiddleware(async (ctx) => {
            if (ctx.path !== "/sign-up/email") {
                return;
            }
            if (!ctx.body?.email.endsWith("@example.com")) {
                throw new APIError("BAD_REQUEST", {
                    message: "Email must end with @example.com",
                });
            }
        }),
    },
});
```

----------------------------------------

TITLE: Configuring Email Verification Sender with Better Auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to configure the `sendVerificationEmail` function within Better Auth's `emailVerification` options. It uses an external `sendEmail` utility to send a verification email to the user's address, including a verification URL. This function is triggered when email verification is initiated.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/email.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from 'better-auth';
import { sendEmail } from './email'; // your email sending function

export const auth = betterAuth({
    emailVerification: {
        sendVerificationEmail: async ({ user, url, token }, request) => {
            await sendEmail({
                to: user.email,
                subject: 'Verify your email address',
                text: `Click the link to verify your email: ${url}`
            })
        }
    }
})
```

----------------------------------------

TITLE: Mounting Better Auth Handler in Next.js
DESCRIPTION: This snippet shows how to set up the Better Auth handler in a Next.js App Router catch-all route file. It imports the auth configuration and uses the `toNextJsHandler` helper to export the necessary HTTP methods.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/installation.mdx#_snippet_14

LANGUAGE: ts
CODE:
```
import { auth } from "@/lib/auth"; // path to your auth file
import { toNextJsHandler } from "better-auth/next-js";

export const { POST, GET } = toNextJsHandler(auth);
```

----------------------------------------

TITLE: Configure BETTER_AUTH_SECRET (.env)
DESCRIPTION: Adds the `BETTER_AUTH_SECRET` environment variable to your `.env` file. This variable is crucial for the library's internal encryption and hashing operations. A strong, random value is required.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/installation.mdx#_snippet_1

LANGUAGE: txt
CODE:
```
BETTER_AUTH_SECRET=
```

----------------------------------------

TITLE: Accessing User Session with useSession Hook in React Native
DESCRIPTION: This snippet demonstrates how to use the `authClient.useSession` hook to retrieve and access the current user's session data within a React Native component. The session data is cached in SecureStore on native platforms, which helps eliminate loading spinners on app reload, though this behavior can be disabled.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/expo.mdx#_snippet_16

LANGUAGE: tsx
CODE:
```
import { authClient } from "@/lib/auth-client";

export default function App() {
    const { data: session } = authClient.useSession();

    return <Text>Welcome, {session.user.name}</Text>;
}
```

----------------------------------------

TITLE: Updating User Information with Better Auth Client (TypeScript)
DESCRIPTION: This snippet demonstrates how to update a user's profile information, such as image and name, using the `updateUser` function provided by the Better Auth client. It takes an object containing the fields to be updated.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/users-accounts.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
await authClient.updateUser({
    image: "https://example.com/image.jpg",
    name: "John Doe",
})
```

----------------------------------------

TITLE: Clerk User Migration Script (TypeScript)
DESCRIPTION: This TypeScript script provides functions for migrating user data from Clerk to Better Auth. It includes utilities for parsing CSV data exported from Clerk, fetching additional user details via the Clerk API, and generating backup codes for two-factor authentication. It's designed to be saved as `scripts/migrate-clerk.ts`.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/clerk-migration-guide.mdx#_snippet_6

LANGUAGE: typescript
CODE:
```
import { generateRandomString, symmetricEncrypt } from "better-auth/crypto";

import { auth } from "@/lib/auth"; // import your auth instance

function getCSVData(csv: string) {
    const lines = csv.split('\n').filter(line => line.trim());
    const headers = lines[0]?.split(',').map(header => header.trim()) || [];
    const jsonData = lines.slice(1).map(line => {
        const values = line.split(',').map(value => value.trim());
        return headers.reduce((obj, header, index) => {
            obj[header] = values[index] || '';
            return obj;
        }, {} as Record<string, string>);
    });

    return jsonData as Array<{
        id: string;
        first_name: string;
        last_name: string;
        username: string;
        primary_email_address: string;
        primary_phone_number: string;
        verified_email_addresses: string;
        unverified_email_addresses: string;
        verified_phone_numbers: string;
        unverified_phone_numbers: string;
        totp_secret: string;
        password_digest: string;
        password_hasher: string;
    }>;
}

const exportedUserCSV = await Bun.file("exported_users.csv").text(); // this is the file you downloaded from Clerk

async function getClerkUsers(totalUsers: number) {
    const clerkUsers: {
        id: string;
        first_name: string;
        last_name: string;
        username: string;
        image_url: string;
        password_enabled: boolean;
        two_factor_enabled: boolean;
        totp_enabled: boolean;
        backup_code_enabled: boolean;
        banned: boolean;
        locked: boolean;
        lockout_expires_in_seconds: number;
        created_at: number;
        updated_at: number;
        external_accounts: {
            id: string;
            provider: string;
            identification_id: string;
            provider_user_id: string;
            approved_scopes: string;
            email_address: string;
            first_name: string;
            last_name: string;
            image_url: string;
            created_at: number;
            updated_at: number;
        }[]
    }[] = [];
    for (let i = 0; i < totalUsers; i += 500) {
        const response = await fetch(`https://api.clerk.com/v1/users?offset=${i}&limit=${500}`, {
            headers: {
                'Authorization': `Bearer ${process.env.CLERK_SECRET_KEY}`
            }
        });
        if (!response.ok) {
            throw new Error(`Failed to fetch users: ${response.statusText}`);
        }
        const clerkUsersData = await response.json();
        // biome-ignore lint/suspicious/noExplicitAny: <explanation>
        clerkUsers.push(...clerkUsersData as any);
    }
    return clerkUsers;
}


export async function generateBackupCodes(
    secret: string,
) {
    const key = secret;
    const backupCodes = Array.from({ length: 10 })
        .fill(null)
        .map(() => generateRandomString(10, "a-z", "0-9", "A-Z"))
```

----------------------------------------

TITLE: Replacing Clerk Middleware with Better Auth Middleware
DESCRIPTION: This TypeScript snippet provides a Next.js middleware function that integrates with Better Auth's session management. It checks for a session cookie and redirects users based on their authentication status and the requested path, ensuring protected routes are accessible only to authenticated users and preventing authenticated users from accessing login/signup pages.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/clerk-migration-guide.mdx#_snippet_13

LANGUAGE: ts
CODE:
```
import { NextRequest, NextResponse } from "next/server";
import { getSessionCookie } from "better-auth/cookies";
export async function middleware(request: NextRequest) {
    const sessionCookie = getSessionCookie(request);
    const { pathname } = request.nextUrl;
    if (sessionCookie && ["/login", "/signup"].includes(pathname)) {
      return NextResponse.redirect(new URL("/dashboard", request.url));
    }
    if (!sessionCookie && pathname.startsWith("/dashboard")) {
      return NextResponse.redirect(new URL("/login", request.url));
    }
    return NextResponse.next();
}

export const config = {
    matcher: ["/dashboard", "/login", "/signup"]
};
```

----------------------------------------

TITLE: Requiring Email Verification for Login with Better Auth (TypeScript)
DESCRIPTION: This snippet configures Better Auth to enforce email verification before a user can successfully log in using email and password. When `emailAndPassword.requireEmailVerification` is set to `true`, `sendVerificationEmail` is called every time an unverified user attempts to sign in.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/email.mdx#_snippet_2

LANGUAGE: TypeScript
CODE:
```
export const auth = betterAuth({
    emailAndPassword: {
        requireEmailVerification: true
    }
})
```

----------------------------------------

TITLE: Defining a GET Endpoint in a Better Auth Plugin
DESCRIPTION: This snippet demonstrates how to define a custom GET endpoint within a Better Auth plugin using `createAuthEndpoint`. It illustrates the structure for adding endpoints to a plugin's configuration and shows how to return a JSON response. The `ctx` object provides access to Better Auth specific contexts for database interaction, session management, and more.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/plugins.mdx#_snippet_3

LANGUAGE: TypeScript
CODE:
```
import { createAuthEndpoint } from "better-auth/api";

const myPlugin = ()=> {
    return {
        id: "my-plugin",
        endpoints: {
            getHelloWorld: createAuthEndpoint("/my-plugin/hello-world", {
                method: "GET",
            }, async(ctx) => {
                return ctx.json({
                    message: "Hello World"
                })
            })
        }
    } satisfies BetterAuthPlugin
}
```

----------------------------------------

TITLE: Initializing a Better Auth Server Plugin (TypeScript)
DESCRIPTION: This snippet shows the basic structure for a Better Auth server plugin. It imports the necessary types and exports a function that returns an object with a unique ID, serving as the minimal valid plugin definition.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/your-first-plugin.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { createAuthClient } from "better-auth/client";
import type { BetterAuthPlugin } from "better-auth";

export const birthdayPlugin = () =>
  ({
    id: "birthdayPlugin",
  } satisfies BetterAuthPlugin);
```

----------------------------------------

TITLE: Setting Global Rate Limit Window and Max Requests (TypeScript)
DESCRIPTION: This example illustrates how to configure the global rate limit window (in seconds) and the maximum number of requests allowed within that window for all client-initiated requests.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/rate-limit.mdx#_snippet_2

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";

export const auth = betterAuth({
    //...other options
    rateLimit: {
        window: 60, // time window in seconds
        max: 100, // max requests in the window
    },
})
```

----------------------------------------

TITLE: Register Cross-Platform Passkey with better-auth Client (TypeScript)
DESCRIPTION: Calls the `addPasskey` function on the `passkey` plugin, specifying `authenticatorAttachment: 'cross-platform'`. This restricts the registration process to cross-platform authenticators, such as security keys or devices scanned via QR code.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/passkey.mdx#_snippet_5

LANGUAGE: ts
CODE:
```
// Register a cross-platform passkey showing only a QR code
// for the user to scan as well as the option to plug in a security key
const { data, error } = await authClient.passkey.addPasskey({
  authenticatorAttachment: 'cross-platform'
});
```

----------------------------------------

TITLE: Check Role Permissions (Client)
DESCRIPTION: Use the `authClient.organization.checkRolePermission` function on the client to check if a specific role has certain permissions. This is useful after defining roles and permissions to avoid repeated server checks. It supports checking multiple permissions for a given role.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/organization.mdx#_snippet_40

LANGUAGE: ts
CODE:
```
const canCreateProject = await authClient.organization.checkRolePermission({
	permissions: {
		organization: ["delete"],
	},
	role: "admin",
});

// You can also check multiple resource permissions at the same time
const canCreateProjectAndCreateSale = await authClient.organization.checkRolePermission({
	permissions: {
		organization: ["delete"],
    member: ["delete"]
	},
	role: "admin",
});
```

----------------------------------------

TITLE: Getting Session in Astro (Astro)
DESCRIPTION: Illustrates how to access the server-side session in an Astro component's frontmatter by passing `Astro.request.headers` to `auth.api.getSession`. Requires importing the `auth` instance.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_17

LANGUAGE: Astro
CODE:
```
---
import { auth } from "./auth";

const session = await auth.api.getSession({
	headers: Astro.request.headers,
});
---
```

----------------------------------------

TITLE: Configure Email/Password Authentication - Better Auth - TypeScript
DESCRIPTION: Shows how to enable email and password authentication by configuring the `betterAuth` instance. It highlights the `emailAndPassword.enabled` option to activate this method.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth"

export const auth = betterAuth({
    emailAndPassword: {    // [!code highlight]
        enabled: true // [!code highlight]
    } // [!code highlight]
})
```

----------------------------------------

TITLE: Generating Better Auth Secret Key with CLI (Bash)
DESCRIPTION: This command generates a secure secret key essential for a Better Auth instance. This key is crucial for cryptographic operations and securing the application.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/cli.mdx#_snippet_3

LANGUAGE: bash
CODE:
```
npx @better-auth/cli@latest secret
```

----------------------------------------

TITLE: Performing Email Sign-In in a Next.js Server Action
DESCRIPTION: This snippet illustrates how to perform an email sign-in operation within a Next.js Server Action using the configured Better Auth instance. It calls 'auth.api.signInEmail' with the user's email and password in the request body.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/next.mdx#_snippet_6

LANGUAGE: TypeScript
CODE:
```
"use server";
import { auth } from "@/lib/auth"

const signIn = async () => {
    await auth.api.signInEmail({
        body: {
            email: "user@email.com",
            password: "password"
        }
    })
}
```

----------------------------------------

TITLE: Configuring GitHub Social Provider (TypeScript)
DESCRIPTION: This code snippet illustrates how to integrate social authentication providers, specifically GitHub, into your Better Auth configuration. You need to provide your GitHub client ID and client secret, typically sourced from environment variables, to enable this functionality.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/guides/supabase-migration-guide.mdx#_snippet_3

LANGUAGE: ts
CODE:
```
import { admin, anonymous } from "better-auth/plugins";

export const auth = betterAuth({
    database: new Pool({ 
        connectionString: process.env.DATABASE_URL 
    }),
    emailAndPassword: { 
        enabled: true,
    },
    socialProviders: {
        github: {
            clientId: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
        }
    }
})
```

----------------------------------------

TITLE: Getting Session in a Next.js Server Component (RSC)
DESCRIPTION: This snippet shows how to fetch the user session within a React Server Component (RSC) in Next.js. It utilizes 'auth.api.getSession' with request headers to check authentication status and conditionally render content based on the session's presence.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/next.mdx#_snippet_4

LANGUAGE: TSX
CODE:
```
import { auth } from "@/lib/auth"
import { headers } from "next/headers"

export async function ServerComponent() {
    const session = await auth.api.getSession({
        headers: await headers()
    })
    if(!session) {
        return <div>Not authenticated</div>
    }
    return (
        <div>
            <h1>Welcome {session.user.name}</h1>
        </div>
    )
}
```

----------------------------------------

TITLE: Getting Session in a Next.js Server Action
DESCRIPTION: This snippet demonstrates how to retrieve the user session within a Next.js Server Action. It uses the 'auth.api.getSession' method, passing the request headers obtained from 'next/headers' to authenticate the session on the server.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/next.mdx#_snippet_3

LANGUAGE: TSX
CODE:
```
import { auth } from "@/lib/auth"
import { headers } from "next/headers"

const someAuthenticatedAction = async () => {
    "use server";
    const session = await auth.api.getSession({
        headers: await headers()
    })
};
```

----------------------------------------

TITLE: Creating Auth Middleware with Better Auth in Nitro.js
DESCRIPTION: This snippet defines `requireAuth`, an event handler that acts as middleware to enforce authentication. It uses `better-auth/node` to get the session from request headers and throws a 401 Unauthorized error if no session is found. The authenticated session is then saved to `event.context.auth` for subsequent use within the route handler.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/nitro.mdx#_snippet_12

LANGUAGE: TypeScript
CODE:
```
import { EventHandler, H3Event } from "h3";
import { fromNodeHeaders } from "better-auth/node";

/**
 * Middleware used to require authentication for a route.
 *
 * Can be extended to check for specific roles or permissions.
 */
export const requireAuth: EventHandler = async (event: H3Event) => {
  const headers = event.headers;

  const session = await auth.api.getSession({
    headers: headers,
  });
  if (!session)
    throw createError({
      statusCode: 401,
      statusMessage: "Unauthorized",
    });
  // You can save the session to the event context for later use
  event.context.auth = session;
};
```

----------------------------------------

TITLE: Triggering Forget Password Flow (TypeScript)
DESCRIPTION: This code initiates the password reset process by calling `authClient.forgetPassword`. It sends a reset password link to the specified email address and defines a `redirectTo` URL for post-reset redirection, handling both valid and invalid token scenarios.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_10

LANGUAGE: typescript
CODE:
```
const { data, error } = await authClient.forgetPassword({
  email: "test@example.com",
  redirectTo: "/reset-password",
});
```

----------------------------------------

TITLE: Signing Up User with Username using BetterAuth Client
DESCRIPTION: This code demonstrates how to register a new user including a username, using the 'signUp.email' function from the 'better-auth' client. It requires 'email', 'name', 'password', and the new 'username' property in the data object.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/username.mdx#_snippet_3

LANGUAGE: ts
CODE:
```
const data = await authClient.signUp.email({
    email: "email@domain.com",
    name: "Test User",
    password: "password1234",
    username: "test"
})
```

----------------------------------------

TITLE: Mapping and Translating Better Auth Error Codes in TypeScript
DESCRIPTION: This comprehensive example demonstrates how to use the `authClient.$ERROR_CODES` object to map and translate server-returned error codes into custom, localized messages. It defines a type for error translations and a utility function `getErrorMessage` to retrieve messages based on the error code and desired language, then applies it after a `signUp` attempt.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/client.mdx#_snippet_12

LANGUAGE: TypeScript
CODE:
```
const authClient = createAuthClient();

type ErrorTypes = Partial<
	Record<
		keyof typeof authClient.$ERROR_CODES,
		{
			en: string;
			es: string;
		}
	>
>;

const errorCodes = {
	USER_ALREADY_EXISTS: {
		en: "user already registered",
		es: "usuario ya registrada",
	},
} satisfies ErrorTypes;

const getErrorMessage = (code: string, lang: "en" | "es") => {
	if (code in errorCodes) {
		return errorCodes[code as keyof typeof errorCodes][lang];
	}
	return "";
};


const { error } = await authClient.signUp.email({
	email: "user@email.com",
	password: "password",
	name: "User",
});
if(error?.code){
    alert(getErrorMessage(error.code, "en"));
}
```

----------------------------------------

TITLE: Configuring Rate Limiting with better-auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to configure rate limiting for the `better-auth` library. It shows how to enable rate limiting, set the window and maximum request limits, define custom rules for specific paths, and specify the storage mechanism for rate limit data. It also covers the `modelName` for database storage.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/options.mdx#_snippet_16

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
export const auth = betterAuth({
	rateLimit: {
		enabled: true,
		window: 10,
		max: 100,
		customRules: {
			"/example/path": {
				window: 10,
				max: 100
			}
		},
		storage: "memory",
		modelName: "rateLimit"
	}
})
```

----------------------------------------

TITLE: Access Extended User Schema Fields After Signup
DESCRIPTION: Demonstrates how to provide values for additional fields during signup and access them from the returned user object.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/database.mdx#_snippet_8

LANGUAGE: typescript
CODE:
```
//on signup
const res = await auth.api.signUpEmail({
  email: "test@example.com",
  password: "password",
  name: "John Doe",
  lang: "fr",
});

//user object
res.user.role; // > "admin"
res.user.lang; // > "fr"
```

----------------------------------------

TITLE: Getting Social Provider Access Token using authClient (TypeScript)
DESCRIPTION: This snippet demonstrates how to retrieve an access token for a social provider on the client-side using `authClient.getAccessToken`. It requires `providerId` and optionally `accountId`. The token will be refreshed if expired.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/oauth.mdx#_snippet_5

LANGUAGE: TypeScript
CODE:
```
const { accessToken } = await authClient.getAccessToken({
  providerId: "google", // or any other provider id
  accountId: "accountId", // optional, if you want to get the access token for a specific account
})
```

----------------------------------------

TITLE: Getting Session on Server with `authClient.getSession` (TSX)
DESCRIPTION: Shows how to use `authClient.getSession` on the server by passing request headers via `fetchOptions`. This approach is useful when `authClient` is required for other server-side functionalities, enabling it to access necessary cookie information.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/reference/faq.mdx#_snippet_3

LANGUAGE: TSX
CODE:
```
import { authClient } from "./auth-client";
import { headers } from "next/headers";

const session = await authClient.getSession({
    fetchOptions:{
      headers: await headers()
    }
})
```

----------------------------------------

TITLE: Configuring Two-Factor Plugin (TypeScript)
DESCRIPTION: Explains how to add the `twoFactor` plugin to your Better Auth server instance. Import the plugin and include it in the `plugins` array of the `betterAuth` configuration object. This enables 2FA functionality.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/basic-usage.mdx#_snippet_22

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth"
import { twoFactor } from "better-auth/plugins" // [!code highlight]

export const auth = betterAuth({
    //...rest of the options
    plugins: [ // [!code highlight]
        twoFactor() // [!code highlight]
    ] // [!code highlight]
})
```

----------------------------------------

TITLE: Add Admin Plugin to Server Config (TypeScript)
DESCRIPTION: Add the `admin` plugin to the `plugins` array in your `betterAuth` configuration file (`auth.ts`). This enables the server-side administrative functions for user management.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/admin.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { admin } from "better-auth/plugins" // [!code highlight]

export const auth = betterAuth({
    // ... other config options
    plugins: [
        admin() // [!code highlight]
    ]
})
```

----------------------------------------

TITLE: Installing Bearer Plugin with better-auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to integrate the Bearer plugin into your `better-auth` setup. It imports `betterAuth` and the `bearer` plugin, then configures `betterAuth` to use the Bearer plugin, enabling token-based authentication for your API.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/bearer.mdx#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins";

export const auth = betterAuth({
    plugins: [bearer()]
});
```

----------------------------------------

TITLE: Configuring CORS for Better Auth with Express.js in TypeScript
DESCRIPTION: This code snippet illustrates how to add Cross-Origin Resource Sharing (CORS) support to an Express.js server integrated with Better Auth. It uses the cors middleware to define allowed origins, HTTP methods, and enable credential passing, ensuring secure communication between different domains.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/integrations/express.mdx#_snippet_1

LANGUAGE: TypeScript
CODE:
```
import express from "express";
import cors from "cors"; // Import the CORS middleware
import { toNodeHandler, fromNodeHeaders } from "better-auth/node";
import { auth } from "./auth";

const app = express();
const port = 3005;

// Configure CORS middleware
app.use(
  cors({
    origin: "http://your-frontend-domain.com", // Replace with your frontend's origin
    methods: ["GET", "POST", "PUT", "DELETE"], // Specify allowed HTTP methods
    credentials: true // Allow credentials (cookies, authorization headers, etc.)
  })
);
```

----------------------------------------

TITLE: Modifying Request Context with Better Auth Before Hook (TypeScript)
DESCRIPTION: This 'before' hook demonstrates how to modify the request context for a specific path (`/sign-up/email`). It returns an updated `context` object, allowing for changes to the request body or other context properties before the endpoint execution.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/hooks.mdx#_snippet_1

LANGUAGE: TypeScript
CODE:
```
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";

export const auth = betterAuth({
    hooks: {
        before: createAuthMiddleware(async (ctx) => {
            if (ctx.path === "/sign-up/email") {
                return {
                    context: {
                        ...ctx,
                        body: {
                            ...ctx.body,
                            name: "John Doe",
                        },
                    }
                };
            }
        }),
    },
});
```

----------------------------------------

TITLE: Authorizing Subscription Management for Organizations (TypeScript)
DESCRIPTION: This `authorizeReference` function is crucial for verifying user permissions before allowing subscription management for an organization. It queries the database to find a member record matching the user and `referenceId` (organization ID) and grants permission if the user's role is 'owner' or 'admin'. This ensures only authorized users can manage organization subscriptions.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/stripe.mdx#_snippet_23

LANGUAGE: TypeScript
CODE:
```
authorizeReference: async ({ user, referenceId, action }) => {
    const member = await db.members.findFirst({
        where: {
            userId: user.id,
            organizationId: referenceId
        }
    });
    
    return member?.role === "owner" || member?.role === "admin";
}
```

----------------------------------------

TITLE: Handling Email Verification Errors on Sign-In (TypeScript)
DESCRIPTION: This code demonstrates how to handle errors when a user attempts to sign in without verifying their email. It checks for a 403 status code and displays an alert message, also showing the original error message.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/authentication/email-password.mdx#_snippet_7

LANGUAGE: typescript
CODE:
```
await authClient.signIn.email(
  {
    email: "email@example.com",
    password: "password",
  },
  {
    onError: (ctx) => {
      // Handle the error
      if (ctx.error.status === 403) {
        alert("Please verify your email address");
      }
      //you can also show the original error message
      alert(ctx.error.message);
    },
  }
);
```

----------------------------------------

TITLE: Configuring Generic OAuth Plugin in better-auth (TypeScript)
DESCRIPTION: This snippet demonstrates how to integrate the `genericOAuth` plugin into the `better-auth` configuration. It shows importing the plugin and adding it to the `plugins` array, including an example configuration for a single OAuth provider with `providerId`, `clientId`, `clientSecret`, and `discoveryUrl`. This setup is crucial for enabling OAuth authentication in the application.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/generic-oauth.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { genericOAuth } from "better-auth/plugins" 

export const auth = betterAuth({
    // ... other config options
    plugins: [ 
        genericOAuth({ 
            config: [ 
                { 
                    providerId: "provider-id", 
                    clientId: "test-client-id", 
                    clientSecret: "test-client-secret", 
                    discoveryUrl: "https://auth.example.com/.well-known/openid-configuration", 
                    // ... other config options 
                }, 
                // Add more providers as needed 
            ] 
        }) 
    ]
})
```

----------------------------------------

TITLE: Configuring Email OTP Plugin in Better Auth (Server-side)
DESCRIPTION: This snippet demonstrates how to add the `emailOTP` plugin to your `betterAuth` configuration. It highlights the `sendVerificationOTP` method, which is crucial for implementing the actual email sending logic for OTPs, allowing for custom integration with email services.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/email-otp.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { emailOTP } from "better-auth/plugins" 

export const auth = betterAuth({
    // ... other config options
    plugins: [
        emailOTP({ 
                async sendVerificationOTP({ email, otp, type}) { 
						// Implement the sendVerificationOTP method to send the OTP to the user's email address 
					}, 
            }) 
        ]
})
```

----------------------------------------

TITLE: Integrate Custom Roles into Server Plugin TypeScript
DESCRIPTION: Shows how to pass the custom access controller (`ac`) and the defined roles (owner, admin, member, myCustomRole) to the server-side `organization` plugin when initializing `betterAuth`.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/organization.mdx#_snippet_36

LANGUAGE: typescript
CODE:
```
import { betterAuth } from "better-auth"
import { organization } from "better-auth/plugins"
import { ac, owner, admin, member } from "@/auth/permissions"

export const auth = betterAuth({
    plugins: [
        organization({
            ac,
            roles: {
                owner,
                admin,
                member,
                myCustomRole
            }
        }),
    ],
});
```

----------------------------------------

TITLE: Add API Key Plugin to Better Auth Server
DESCRIPTION: This TypeScript snippet shows how to integrate the API Key plugin into your Better Auth server instance. It involves importing the necessary plugin module and including it in the `plugins` array during the `betterAuth` initialization.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/api-key.mdx#_snippet_0

LANGUAGE: ts
CODE:
```
import { betterAuth } from "better-auth"
import { apiKey } from "better-auth/plugins"

export const auth = betterAuth({
    plugins: [ // [!code highlight]
        apiKey() // [!code highlight]
    ] // [!code highlight]
})
```

----------------------------------------

TITLE: Verify One-Time Password (OTP) Code (TypeScript)
DESCRIPTION: Shows how to verify a user-provided One-Time Password (OTP) code using the `authClient.twoFactor.verifyOtp` method. It includes examples of handling success and error scenarios using the provided callback options, allowing for custom UI updates based on verification results.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/plugins/2fa.mdx#_snippet_15

LANGUAGE: TypeScript
CODE:
```
const verifyOtp = async (code: string) => {
    await authClient.twoFactor.verifyOtp({ code }, {
        onSuccess(){
            //redirect the user on success
        },
        onError(ctx){
            alert(ctx.error.message)
        }
    })
}
```

----------------------------------------

TITLE: Handling API Errors (TypeScript)
DESCRIPTION: Demonstrates how to implement error handling for server-side API calls using a `try...catch` block and checking if the caught error is an instance of `APIError` to access its message and status.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/api.mdx#_snippet_5

LANGUAGE: ts
CODE:
```
import { APIError } from "better-auth/api";

try {
    await auth.api.signInEmail({
        body: {
            email: "",
            password: ""
        }
    })
} catch (error) {
    if (error instanceof APIError) {
        console.log(error.message, error.status)
    }
}
```

----------------------------------------

TITLE: Changing User Password with Better Auth Client (TypeScript)
DESCRIPTION: This snippet demonstrates how to change a user's password using the `changePassword` function from the Better Auth client. It requires the `newPassword` and `currentPassword` for authentication. The `revokeOtherSessions` option can be used to log out the user from all other active sessions.
SOURCE: https://github.com/better-auth/better-auth/blob/main/docs/content/docs/concepts/users-accounts.mdx#_snippet_4

LANGUAGE: TypeScript
CODE:
```
await authClient.changePassword({
    newPassword: "newPassword123",
    currentPassword: "oldPassword123",
    revokeOtherSessions: true, // revoke all other sessions the user is signed into
});
```