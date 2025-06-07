import Elysia from "elysia";

import { auth } from "@lib/auth";

export default new Elysia({ name: "Services.Auth" })
    .mount(auth.handler)
    .macro({
        auth: {
            async resolve({ status, request: { headers } }) {
                const session = await auth.api.getSession({ headers });

                // If no session is found, return a 401 status.
                if (!session) {
                    return status(401);
                }

                // Fetch the data from the database.
                // const user = await User.findById(session.user.id);
                // if (!user) {
                //     return status(404);
                // }

                // Return the user data.
                return { user: session.user, session: session.session };
            }
        }
    });
