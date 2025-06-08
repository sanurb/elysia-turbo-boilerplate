import type { ReactNode } from "react"
import { Providers } from "./providers"

import "@/app/globals.css";


export default function RootLayout({ children }: { children: ReactNode }) {
    return (
        <html lang="en">
            <body>
                <Providers>{children}</Providers>
            </body>
        </html>
    )
}
