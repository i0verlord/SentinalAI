import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "SentinelAI | Threat monitor",
    description: "Log anomaly detection and incident triage console",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
