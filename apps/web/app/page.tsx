"use client";

import { useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowUpRight, Check, Clock3, Database, FileUp, LoaderCircle, LockKeyhole, RefreshCw, Search, Server, ShieldCheck, Sparkles, X } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type Alert, type AlertDetail, type Overview, type TrafficPoint } from "@/lib/api";

const numberFormat = new Intl.NumberFormat("en-US");
const timeFormat = (value: string) => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function severityFor(alert: Alert) {
    if (alert.incident) return alert.incident.severity;
    return alert.ssh_failures >= 8 || alert.error_rate >= 80 ? "High" : "Medium";
}

export default function Home() {
    const [overview, setOverview] = useState<Overview | null>(null);
    const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [selected, setSelected] = useState<AlertDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [detailLoading, setDetailLoading] = useState(false);
    const [error, setError] = useState("");
    const [severityFilter, setSeverityFilter] = useState("all");

    useEffect(() => {
        let active = true;
        const load = async () => {
            try {
                const [overviewResult, trafficResult, alertResult] = await Promise.all([api.overview(), api.traffic(), api.alerts()]);
                if (!active) return;
                setOverview(overviewResult);
                setTraffic(trafficResult);
                setAlerts(alertResult);
                setError("");
            } catch (caught) {
                if (active) setError(caught instanceof Error ? caught.message : "Unable to reach the API.");
            } finally {
                if (active) setLoading(false);
            }
        };
        void load();
        const timer = window.setInterval(() => void load(), 15000);
        return () => {
            active = false;
            window.clearInterval(timer);
        };
    }, []);

    async function refresh() {
        setBusy(true);
        try {
            const [overviewResult, trafficResult, alertResult] = await Promise.all([api.overview(), api.traffic(), api.alerts()]);
            setOverview(overviewResult);
            setTraffic(trafficResult);
            setAlerts(alertResult);
            setError("");
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Unable to reach the API.");
        } finally {
            setBusy(false);
        }
    }

    async function openAlert(alert: Alert) {
        setSelected(null);
        setDetailLoading(true);
        try {
            setSelected(await api.alert(alert.id));
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Unable to load alert details.");
        } finally {
            setDetailLoading(false);
        }
    }

    async function simulateTraffic() {
        setBusy(true);
        try {
            await api.simulate();
            await refresh();
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Simulation failed.");
        } finally {
            setBusy(false);
        }
    }

    async function uploadFile(event: React.ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        if (!file) return;
        setBusy(true);
        try {
            const result = await api.upload(file, "auto");
            setError(result.skipped ? `${result.parsed} lines parsed; ${result.skipped} lines skipped.` : "");
            await refresh();
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Upload failed.");
        } finally {
            setBusy(false);
            event.target.value = "";
        }
    }

    async function requestTriage() {
        if (!selected) return;
        setBusy(true);
        try {
            const updated = await api.triage(selected.id);
            setSelected({ ...selected, ...updated });
            await refresh();
        } catch (caught) {
            setError(caught instanceof Error ? caught.message : "Triage request failed.");
        } finally {
            setBusy(false);
        }
    }

    const visibleAlerts = alerts.filter((alert) => severityFilter === "all" || severityFor(alert).toLowerCase() === severityFilter);

    return (
        <main className="shell">
            <header className="topbar">
                <div className="brand">
                    <span className="brand-mark">
                        <ShieldCheck size={18} strokeWidth={2.2} />
                    </span>
                    <span>
                        SentinelAI<small>Security observability</small>
                    </span>
                </div>
                <div className="topbar-right">
                    <span>
                        <i className="live-dot" />
                        Live monitor
                    </span>
                    <span>{overview?.latest_window ? `Updated ${timeFormat(overview.latest_window)}` : "Waiting for events"}</span>
                    <button className="icon-button" title="Refresh data" aria-label="Refresh data" onClick={() => void refresh()} disabled={busy}>
                        <RefreshCw size={15} className={busy ? "animate-spin" : ""} />
                    </button>
                </div>
            </header>

            <div className="content">
                <section className="page-heading">
                    <div>
                        <p className="eyebrow">Threat operations / Overview</p>
                        <h1>Signal, without the noise.</h1>
                        <p className="subheading">Live log activity and machine-flagged behavior across your infrastructure.</p>
                    </div>
                    <div className="actions">
                        <label className="button" title="Upload Nginx or SSH log file">
                            <FileUp size={15} /> Upload logs
                            <input type="file" accept=".log,.txt,text/plain" onChange={(event) => void uploadFile(event)} hidden disabled={busy} />
                        </label>
                        <button className="button button-primary" onClick={() => void simulateTraffic()} disabled={busy}>
                            {busy ? <LoaderCircle size={15} className="animate-spin" /> : <Activity size={15} />}
                            Simulate traffic
                        </button>
                    </div>
                </section>

                {error && (
                    <div className="error-banner" role="status">
                        <span>{error}</span>
                        <button onClick={() => setError("")} aria-label="Dismiss message">
                            <X size={14} />
                        </button>
                    </div>
                )}

                <section className="kpis" aria-label="Key metrics">
                    <article className="kpi">
                        <div className="kpi-label">Logs processed</div>
                        <div className="kpi-value">
                            {loading ? "—" : numberFormat.format(overview?.total_logs ?? 0)}
                            <span className="kpi-note">all sources</span>
                        </div>
                    </article>
                    <article className="kpi kpi-alert">
                        <div className="kpi-label">Active anomaly alerts</div>
                        <div className="kpi-value">
                            {loading ? "—" : numberFormat.format(overview?.active_alerts ?? 0)}
                            <span className="kpi-note">requires review</span>
                        </div>
                    </article>
                    <article className="kpi kpi-rate">
                        <div className="kpi-label">HTTP error rate</div>
                        <div className="kpi-value">
                            {loading ? "—" : `${(overview?.error_rate ?? 0).toFixed(1)}%`}
                            <span className="kpi-note">4xx + 5xx</span>
                        </div>
                    </article>
                </section>

                <section className="main-grid">
                    <article className="panel">
                        <div className="panel-header">
                            <div>
                                <h2 className="panel-title">Request volume</h2>
                                <p className="panel-caption">Minute-by-minute traffic, anomaly windows highlighted</p>
                            </div>
                            <div className="legend">
                                <span>
                                    <i /> Normal
                                </span>
                                <span>
                                    <i className="legend-red" /> Flagged
                                </span>
                            </div>
                        </div>
                        <div className="chart-wrap">
                            {traffic.length ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <LineChart data={traffic} margin={{ top: 14, right: 16, left: -18, bottom: 0 }}>
                                        <CartesianGrid stroke="#e8ede7" strokeDasharray="3 5" vertical={false} />
                                        <XAxis dataKey="timestamp" tickFormatter={timeFormat} axisLine={false} tickLine={false} tick={{ fill: "#87938b", fontSize: 10 }} minTickGap={28} />
                                        <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#87938b", fontSize: 10 }} />
                                        <Tooltip labelFormatter={(label) => new Date(String(label)).toLocaleString()} contentStyle={{ border: "1px solid #dce3dc", borderRadius: 6, fontSize: 11 }} />
                                        <Line type="monotone" dataKey="normal_requests" name="Normal" stroke="#377e9c" strokeWidth={2} dot={false} connectNulls />
                                        <Line type="monotone" dataKey="anomaly_requests" name="Anomaly" stroke="#c94d3e" strokeWidth={2.5} dot={{ r: 3, fill: "#c94d3e", strokeWidth: 0 }} connectNulls />
                                    </LineChart>
                                </ResponsiveContainer>
                            ) : (
                                <div className="empty-state">{loading ? "Loading traffic…" : "No traffic yet. Upload logs or simulate activity."}</div>
                            )}
                        </div>
                    </article>

                    <article className="panel">
                        <div className="panel-header">
                            <div>
                                <h2 className="panel-title">Ingestion sources</h2>
                                <p className="panel-caption">Events retained for investigation</p>
                            </div>
                            <button className="icon-button" title="Refresh source metrics" aria-label="Refresh source metrics" onClick={() => void refresh()}>
                                <RefreshCw size={14} />
                            </button>
                        </div>
                        <div className="source-list">
                            <div className="source-row">
                                <span className="source-name">
                                    <span className="source-icon">
                                        <Server size={14} />
                                    </span>
                                    Nginx access
                                </span>
                                <span className="source-value">HTTP events</span>
                            </div>
                            <div className="source-row">
                                <span className="source-name">
                                    <span className="source-icon">
                                        <LockKeyhole size={14} />
                                    </span>
                                    SSH auth
                                </span>
                                <span className="source-value">Login events</span>
                            </div>
                            <div className="source-row">
                                <span className="source-name">
                                    <span className="source-icon">
                                        <Database size={14} />
                                    </span>
                                    Event storage
                                </span>
                                <span className="source-value">PostgreSQL</span>
                            </div>
                            <div className="source-row">
                                <span className="source-name">
                                    <span className="source-icon">
                                        <Sparkles size={14} />
                                    </span>
                                    Incident triage
                                </span>
                                <span className="source-value">On demand</span>
                            </div>
                        </div>
                        <div className="panel-header" style={{ borderTop: "1px solid #edf0ec", paddingTop: 12 }}>
                            <span className="footer-note">
                                <Clock3 size={13} /> Window size: 1 minute
                            </span>
                            <span className="footer-note">
                                <Check size={13} /> Model: Isolation Forest
                            </span>
                        </div>
                    </article>
                </section>

                <section className="panel alerts-panel">
                    <div className="panel-header">
                        <div>
                            <h2 className="panel-title">Anomaly alerts</h2>
                            <p className="panel-caption">Unusual IP activity grouped into one-minute windows</p>
                        </div>
                        <div className="alerts-tools">
                            <Search size={14} color="#72807a" />
                            <select className="select" aria-label="Filter alerts by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                                <option value="all">All severities</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                    <div className="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>Source IP</th>
                                    <th>Window</th>
                                    <th>Requests</th>
                                    <th>Error rate</th>
                                    <th>Model score</th>
                                    <th>Severity</th>
                                    <th>Triage</th>
                                    <th aria-label="Open details" />
                                </tr>
                            </thead>
                            <tbody>
                                {visibleAlerts.map((alert) => {
                                    const severity = severityFor(alert);
                                    return (
                                        <tr key={alert.id} onClick={() => void openAlert(alert)}>
                                            <td className="ip-cell">{alert.source_ip}</td>
                                            <td>{new Date(alert.window_start).toLocaleString()}</td>
                                            <td>{alert.event_count}</td>
                                            <td>{alert.error_rate.toFixed(0)}%</td>
                                            <td className="score">{alert.anomaly_score.toFixed(3)}</td>
                                            <td>
                                                <span className={`pill pill-${severity.toLowerCase()}`}>
                                                    <i className="status-dot" />
                                                    {severity}
                                                </span>
                                            </td>
                                            <td>{alert.triage_status === "complete" ? "Ready" : alert.triage_status === "unavailable" ? "Not configured" : "Pending"}</td>
                                            <td>
                                                <ArrowUpRight size={14} color="#87938b" />
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                        {!visibleAlerts.length && <div className="empty-state">{loading ? "Loading alerts…" : "No matching anomalies. Your signal is quiet."}</div>}
                    </div>
                    <div className="panel-header" style={{ borderTop: "1px solid #edf0ec", paddingTop: 10, paddingBottom: 10 }}>
                        <span className="footer-note">
                            <AlertTriangle size={13} /> {visibleAlerts.length} alert{visibleAlerts.length === 1 ? "" : "s"} shown
                        </span>
                        <button className="button button-quiet" onClick={() => void refresh()}>
                            <RefreshCw size={13} /> Refresh list
                        </button>
                    </div>
                </section>
            </div>

            {(selected || detailLoading) && (
                <div
                    className="drawer-backdrop"
                    onMouseDown={(event) => {
                        if (event.target === event.currentTarget) setSelected(null);
                    }}
                >
                    <aside className="drawer" role="dialog" aria-modal="true" aria-label="Incident details">
                        <div className="drawer-head">
                            <div>
                                <p className="eyebrow">Alert investigation</p>
                                <h2>{selected?.source_ip ?? "Loading alert…"}</h2>
                            </div>
                            <button className="icon-button" title="Close incident details" aria-label="Close incident details" onClick={() => setSelected(null)}>
                                <X size={17} />
                            </button>
                        </div>
                        {detailLoading || !selected ? (
                            <div className="loading-state">Loading alert evidence…</div>
                        ) : (
                            <div className="drawer-body">
                                <section className="drawer-section">
                                    <span className="drawer-label">Detection window</span>
                                    <p className="incident-copy">
                                        {new Date(selected.window_start).toLocaleString()} · {selected.event_count} events · model score {selected.anomaly_score.toFixed(3)}
                                    </p>
                                </section>
                                <section className="drawer-section">
                                    <span className="drawer-label">AI incident assessment</span>
                                    {selected.incident ? (
                                        <>
                                            <div className="incident-title">
                                                <span>{selected.incident.threat_category}</span>
                                                <span className={`pill pill-${selected.incident.severity.toLowerCase()}`}>{selected.incident.severity}</span>
                                            </div>
                                            <p className="incident-copy">{selected.incident.summary}</p>
                                        </>
                                    ) : (
                                        <div className="no-triage">{selected.triage_status === "unavailable" ? "LLM triage is not configured. Add the provider URL, model, and API key to enable an assessment." : "No assessment is attached to this alert yet. Request triage to analyze a capped sample of the raw evidence."}</div>
                                    )}
                                </section>
                                {selected.incident && (
                                    <section className="drawer-section">
                                        <span className="drawer-label">Suggested remediation</span>
                                        <div className="remediation">{selected.incident.remediation}</div>
                                    </section>
                                )}
                                <section className="drawer-section">
                                    <span className="drawer-label">Evidence sample · {selected.evidence.length} events</span>
                                    <div className="evidence">
                                        {selected.evidence.map((event, index) => (
                                            <div className="evidence-row" key={`${event.timestamp}-${index}`}>
                                                <div className="evidence-meta">
                                                    {timeFormat(event.timestamp)} · {event.event_type} · {event.status_code ?? "—"}
                                                </div>
                                                {event.raw_line}
                                            </div>
                                        ))}
                                    </div>
                                </section>
                            </div>
                        )}
                        {selected && (
                            <div className="drawer-footer">
                                {!selected.incident && (
                                    <button className="button button-primary" onClick={() => void requestTriage()} disabled={busy || selected.triage_status === "unavailable"}>
                                        {busy ? <LoaderCircle size={14} className="animate-spin" /> : <Sparkles size={14} />} Request AI triage
                                    </button>
                                )}
                                {selected.incident && (
                                    <span className="footer-note">
                                        <Check size={13} /> Assessment validated and attached
                                    </span>
                                )}
                            </div>
                        )}
                    </aside>
                </div>
            )}
        </main>
    );
}
