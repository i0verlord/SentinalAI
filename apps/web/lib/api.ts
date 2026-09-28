export type Severity = "Low" | "Medium" | "High" | "Critical";

export type Incident = {
    threat_category: string;
    severity: Severity;
    summary: string;
    remediation: string;
};

export type Alert = {
    id: number;
    source_ip: string;
    window_start: string;
    anomaly_score: number;
    status: string;
    event_count: number;
    error_rate: number;
    unique_endpoints: number;
    ssh_failures: number;
    triage_status: "pending" | "complete" | "unavailable" | "failed";
    incident: Incident | null;
};

export type Overview = {
    total_logs: number;
    active_alerts: number;
    error_rate: number;
    latest_window: string | null;
};

export type TrafficPoint = {
    timestamp: string;
    normal_requests: number | null;
    anomaly_requests: number | null;
};

export type AlertDetail = Alert & {
    evidence: Array<{
        timestamp: string;
        event_type: string;
        source_ip: string;
        http_method: string | null;
        endpoint: string | null;
        status_code: number | null;
        raw_line: string;
    }>;
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, init);
    if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.detail ?? `Request failed (${response.status})`);
    }
    return response.json() as Promise<T>;
}

export const api = {
    overview: () => request<Overview>("/dashboard/overview"),
    traffic: () => request<TrafficPoint[]>("/dashboard/traffic"),
    alerts: () => request<Alert[]>("/alerts"),
    alert: (id: number) => request<AlertDetail>(`/alerts/${id}`),
    simulate: () => request<{ ingested: number; flagged: number }>("/ingestion/simulate", { method: "POST" }),
    upload: (file: File, format: "auto" | "nginx" | "ssh") => {
        const body = new FormData();
        body.set("file", file);
        body.set("format", format);
        return request<{ parsed: number; skipped: number; flagged: number }>("/ingestion/upload", { method: "POST", body });
    },
    triage: (id: number) => request<Alert>(`/alerts/${id}/triage`, { method: "POST" }),
};
