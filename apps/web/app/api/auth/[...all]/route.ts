import { toNextJsHandler } from "better-auth/next-js"
import { auth } from "@/api/lib/auth"

export const { POST, GET } = toNextJsHandler(auth)
