import { useEffect, useState } from "react";
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer
} from "recharts";

const API_URL = "http://localhost:3000";

function LoginPage({ onLogin }) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    async function handleLogin(event) {
        event.preventDefault();

        try {
            setLoading(true);
            setError("");

            const response = await fetch(`${API_URL}/auth/login`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username,
                    password
                })
            });

            let data = {};

            try {
                data = await response.json();
            } catch {
                data = {};
            }

            if (!response.ok) {
                throw new Error(data.error || "Login failed");
            }

            localStorage.setItem("adminToken", data.token);
            onLogin();
        } catch (error) {
            setError(error.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
            <div className="w-full max-w-md">
                <div className="mb-8 text-center">
                    <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-blue-600 text-2xl font-bold text-white">
                        S
                    </div>

                    <h1 className="mt-5 text-3xl font-bold text-white">
                        Secure API Gateway
                    </h1>

                    <p className="mt-2 text-slate-400">
                        Security Monitoring Platform
                    </p>
                </div>

                <form
                    onSubmit={handleLogin}
                    className="rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl"
                >
                    <h2 className="text-xl font-semibold text-white">
                        Administrator Login
                    </h2>

                    <p className="mt-2 text-sm text-slate-400">
                        Sign in to access the security dashboard.
                    </p>

                    {error && (
                        <div className="mt-5 rounded-lg border border-red-800 bg-red-950 px-4 py-3">
                            <p className="text-sm text-red-400">
                                {error}
                            </p>
                        </div>
                    )}

                    <div className="mt-6">
                        <label className="mb-2 block text-sm text-slate-300">
                            Username
                        </label>

                        <input
                            type="text"
                            value={username}
                            onChange={(event) =>
                                setUsername(event.target.value)
                            }
                            placeholder="Enter username"
                            autoComplete="username"
                            required
                            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none focus:border-blue-500"
                        />
                    </div>

                    <div className="mt-5">
                        <label className="mb-2 block text-sm text-slate-300">
                            Password
                        </label>

                        <input
                            type="password"
                            value={password}
                            onChange={(event) =>
                                setPassword(event.target.value)
                            }
                            placeholder="Enter password"
                            autoComplete="current-password"
                            required
                            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none focus:border-blue-500"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="mt-6 w-full rounded-lg bg-blue-600 px-4 py-3 font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        {loading ? "Authenticating..." : "Sign In"}
                    </button>
                </form>
            </div>
        </div>
    );
}

function App() {
    const [authenticated, setAuthenticated] = useState(
        !!localStorage.getItem("adminToken")
    );

    const [page, setPage] = useState("dashboard");
    const [dashboard, setDashboard] = useState(null);
    const [threatHistory, setThreatHistory] = useState([]);
    const [events, setEvents] = useState([]);
    const [requests, setRequests] = useState([]);
    const [blockedIPs, setBlockedIPs] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [showBlockForm, setShowBlockForm] = useState(false);

    const [blockForm, setBlockForm] = useState({
        ip: "",
        reason: "",
        expiresInMinutes: 10
    });

    const token = localStorage.getItem("adminToken");

    const headers = {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
    };

    async function apiRequest(endpoint, options = {}) {
        const currentToken = localStorage.getItem("adminToken");

        const response = await fetch(`${API_URL}${endpoint}`, {
            ...options,
            headers: {
                Authorization: `Bearer ${currentToken || ""}`,
                "Content-Type": "application/json",
                ...(options.headers || {})
            }
        });

        let data;

        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem("adminToken");
            setAuthenticated(false);

            throw new Error(
                data.error || "Authentication expired. Please login again."
            );
        }

        if (!response.ok) {
            throw new Error(data.error || "Request failed");
        }

        return data;
    }

    async function loadDashboard(showLoader = true) {
        try {
            if (showLoader) {
                setLoading(true);
            }

            setError("");

            const dashboardData = await apiRequest(
                "/security/dashboard"
            );

            setDashboard(dashboardData);

            const historyData = await apiRequest(
                "/security/threat-history?minutes=60"
            );

            const history = Array.isArray(historyData.history)
                ? historyData.history
                : [];

            const formattedHistory = history.map((item) => ({
                time: item.time,
                threats: Number(item.threats || 0),
                failedLogins: Number(item.failedLogins || 0),
                unauthorized: Number(item.unauthorized || 0)
            }));

            setThreatHistory(formattedHistory);
        } catch (error) {
            setError(error.message);
        } finally {
            if (showLoader) {
                setLoading(false);
            }
        }
    }

    async function loadEvents() {
        try {
            setLoading(true);
            setError("");

            const data = await apiRequest("/security/events");

            setEvents(data.events || []);
        } catch (error) {
            setError(error.message);
        } finally {
            setLoading(false);
        }
    }

    async function loadRequests() {
        try {
            setLoading(true);
            setError("");

            const data = await apiRequest("/api/requests");

            setRequests(data.requests || []);
        } catch (error) {
            setError(error.message);
        } finally {
            setLoading(false);
        }
    }

    async function loadBlockedIPs() {
        try {
            setLoading(true);
            setError("");

            const data = await apiRequest(
                "/security/blocked-ips"
            );

            setBlockedIPs(data.blockedIPs || []);
        } catch (error) {
            setError(error.message);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        if (!authenticated) {
            return;
        }

        const currentToken = localStorage.getItem("adminToken");

        if (!currentToken) {
            setAuthenticated(false);
            return;
        }

        loadDashboard();
    }, [authenticated]);

    useEffect(() => {
        if (!authenticated) {
            return;
        }

        const interval = setInterval(() => {
            loadDashboard(false);
        }, 10000);

        return () => {
            clearInterval(interval);
        };
    }, [authenticated]);

    function navigate(target) {
        setPage(target);
        setError("");

        if (target === "dashboard") {
            loadDashboard();
        }

        if (target === "events") {
            loadEvents();
        }

        if (target === "requests") {
            loadRequests();
        }

        if (target === "blocked") {
            loadBlockedIPs();
        }
    }

    async function blockIP(event) {
        event.preventDefault();

        try {
            setLoading(true);
            setError("");

            await apiRequest("/security/block-ip", {
                method: "POST",
                body: JSON.stringify({
                    ip: blockForm.ip.trim(),
                    reason:
                        blockForm.reason.trim() ||
                        "Blocked by administrator",
                    expiresInMinutes: Number(
                        blockForm.expiresInMinutes
                    )
                })
            });

            setBlockForm({
                ip: "",
                reason: "",
                expiresInMinutes: 10
            });

            setShowBlockForm(false);

            await loadBlockedIPs();
        } catch (error) {
            setError(error.message);
            setLoading(false);
        }
    }

    async function unblockIP(ip) {
        const confirmed = window.confirm(
            `Unblock IP address ${ip}?`
        );

        if (!confirmed) {
            return;
        }

        try {
            setLoading(true);
            setError("");

            await apiRequest(
                `/security/block-ip/${encodeURIComponent(ip)}`,
                {
                    method: "DELETE"
                }
            );

            await loadBlockedIPs();
        } catch (error) {
            setError(error.message);
            setLoading(false);
        }
    }

    function logout() {
        localStorage.removeItem("adminToken");

        setAuthenticated(false);
        setDashboard(null);
        setThreatHistory([]);
        setEvents([]);
        setRequests([]);
        setBlockedIPs([]);
        setError("");
        setPage("dashboard");
    }

    const cards = dashboard
        ? [
              {
                  title: "Total Requests",
                  value: dashboard.totalRequests,
                  icon: "↗"
              },
              {
                  title: "Threats Detected",
                  value: dashboard.totalThreats,
                  icon: "⚠"
              },
              {
                  title: "Failed Logins",
                  value: dashboard.failedLogins,
                  icon: "🔐"
              },
              {
                  title: "Blocked IPs",
                  value: dashboard.blockedIPs,
                  icon: "🚫"
              },
              {
                  title: "Rate Limit Violations",
                  value: dashboard.rateLimitViolations,
                  icon: "⏱"
              },
              {
                  title: "Unauthorized Access",
                  value: dashboard.unauthorizedAccess,
                  icon: "🛡"
              },
              {
                  title: "Auto-Blocked IPs",
                  value: dashboard.autoBlockedIPs,
                  icon: "⚡"
              },
              {
                  title: "Avg Response Time",
                  value: `${dashboard.averageResponseTime} ms`,
                  icon: "◉"
              }
          ]
        : [];

    if (!authenticated) {
        return (
            <LoginPage
                onLogin={() => setAuthenticated(true)}
            />
        );
    }

    return (
        <div className="min-h-screen bg-slate-950 text-white">
            <div className="flex min-h-screen">
                <aside className="fixed left-0 top-0 z-20 flex h-screen w-64 flex-col border-r border-slate-800 bg-slate-900">
                    <div className="border-b border-slate-800 px-6 py-6">
                        <div className="flex items-center gap-3">
                            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600 text-xl font-bold">
                                S
                            </div>

                            <div>
                                <h1 className="font-bold">
                                    Secure Gateway
                                </h1>

                                <p className="text-xs text-slate-400">
                                    Security Platform
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="px-4 py-6">
                        <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                            Monitoring
                        </p>

                        <button
                            onClick={() =>
                                navigate("dashboard")
                            }
                            className={`mb-2 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm ${
                                page === "dashboard"
                                    ? "bg-blue-600 text-white"
                                    : "text-slate-300 hover:bg-slate-800"
                            }`}
                        >
                            <span>▣</span>
                            Dashboard
                        </button>

                        <button
                            onClick={() =>
                                navigate("events")
                            }
                            className={`mb-2 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm ${
                                page === "events"
                                    ? "bg-blue-600 text-white"
                                    : "text-slate-300 hover:bg-slate-800"
                            }`}
                        >
                            <span>⚠</span>
                            Security Events
                        </button>

                        <button
                            onClick={() =>
                                navigate("requests")
                            }
                            className={`mb-2 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm ${
                                page === "requests"
                                    ? "bg-blue-600 text-white"
                                    : "text-slate-300 hover:bg-slate-800"
                            }`}
                        >
                            <span>↗</span>
                            API Requests
                        </button>

                        <button
                            onClick={() =>
                                navigate("blocked")
                            }
                            className={`mb-2 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm ${
                                page === "blocked"
                                    ? "bg-blue-600 text-white"
                                    : "text-slate-300 hover:bg-slate-800"
                            }`}
                        >
                            <span>🚫</span>
                            Blocked IPs
                        </button>
                    </div>

                    <div className="mt-auto border-t border-slate-800 p-4">
                        <div className="mb-3 rounded-lg bg-slate-800 p-3">
                            <p className="text-xs text-slate-500">
                                Logged in as
                            </p>

                            <p className="mt-1 text-sm font-semibold">
                                Administrator
                            </p>

                            <div className="mt-2 flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-green-500"></span>

                                <span className="text-xs text-green-400">
                                    Admin Access
                                </span>
                            </div>
                        </div>

                        <button
                            onClick={logout}
                            className="w-full rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
                        >
                            Logout
                        </button>
                    </div>
                </aside>

                <main className="ml-64 min-h-screen flex-1">
                    <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/95 px-8 py-5 backdrop-blur">
                        <div className="flex items-center justify-between">
                            <div>
                                <h2 className="text-2xl font-bold">
                                    {page === "dashboard" &&
                                        "Security Dashboard"}

                                    {page === "events" &&
                                        "Security Events"}

                                    {page === "requests" &&
                                        "API Requests"}

                                    {page === "blocked" &&
                                        "Blocked IP Management"}
                                </h2>

                                <p className="mt-1 text-sm text-slate-400">
                                    Secure API Gateway
                                </p>
                            </div>

                            <div className="flex items-center gap-4">
                                <div className="flex items-center gap-2">
                                    <span className="h-3 w-3 rounded-full bg-green-500"></span>

                                    <span className="text-sm text-slate-300">
                                        Gateway Online
                                    </span>
                                </div>

                                <button
                                    onClick={() =>
                                        navigate(page)
                                    }
                                    disabled={loading}
                                    className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                                >
                                    {loading
                                        ? "Refreshing..."
                                        : "Refresh"}
                                </button>
                            </div>
                        </div>
                    </header>

                    <div className="p-8">
                        {error && (
                            <div className="mb-6 rounded-lg border border-red-800 bg-red-950 p-4">
                                <div className="flex items-start justify-between gap-4">
                                    <div>
                                        <p className="font-semibold text-red-400">
                                            Error
                                        </p>

                                        <p className="mt-1 text-sm text-red-300">
                                            {error}
                                        </p>
                                    </div>

                                    <button
                                        onClick={() =>
                                            setError("")
                                        }
                                        className="text-red-400 hover:text-red-300"
                                    >
                                        ✕
                                    </button>
                                </div>
                            </div>
                        )}

                        {loading && (
                            <div className="mb-6 rounded-lg border border-blue-800 bg-blue-950 p-4 text-sm text-blue-300">
                                Loading security data...
                            </div>
                        )}

                        {page === "dashboard" &&
                            dashboard && (
                                <DashboardPage
                                    dashboard={dashboard}
                                    cards={cards}
                                    threatHistory={
                                        threatHistory
                                    }
                                />
                            )}

                        {page === "events" && (
                            <EventsPage
                                events={events}
                            />
                        )}

                        {page === "requests" && (
                            <RequestsPage
                                requests={requests}
                            />
                        )}

                        {page === "blocked" && (
                            <BlockedIPsPage
                                blockedIPs={blockedIPs}
                                showBlockForm={
                                    showBlockForm
                                }
                                setShowBlockForm={
                                    setShowBlockForm
                                }
                                blockForm={blockForm}
                                setBlockForm={
                                    setBlockForm
                                }
                                blockIP={blockIP}
                                unblockIP={unblockIP}
                            />
                        )}
                    </div>
                </main>
            </div>
        </div>
    );
}

function DashboardPage({
    dashboard,
    cards,
    threatHistory
}) {
    return (
        <>
            <div className="mb-8">
                <h3 className="text-xl font-semibold">
                    Security Overview
                </h3>

                <p className="mt-1 text-sm text-slate-400">
                    Real-time security statistics from PostgreSQL
                </p>
            </div>

            <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
                {cards.map((card) => (
                    <div
                        key={card.title}
                        className="rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-lg"
                    >
                        <div className="flex items-center justify-between">
                            <p className="text-sm text-slate-400">
                                {card.title}
                            </p>

                            <span className="text-xl">
                                {card.icon}
                            </span>
                        </div>

                        <p className="mt-4 text-3xl font-bold">
                            {card.value}
                        </p>
                    </div>
                ))}
            </div>

            <div className="mt-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <h3 className="text-lg font-semibold">
                            Threat Activity
                        </h3>

                        <p className="mt-1 text-sm text-slate-400">
                            Security activity from PostgreSQL over the last 60 minutes
                        </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-xs">
                        <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full bg-red-500"></span>
                            Threats
                        </div>

                        <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full bg-yellow-500"></span>
                            Failed Logins
                        </div>

                        <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full bg-blue-500"></span>
                            Unauthorized
                        </div>
                    </div>
                </div>

                <div className="mt-6 h-80 w-full">
                    {threatHistory.length > 0 ? (
                        <ResponsiveContainer
                            width="100%"
                            height="100%"
                        >
                            <LineChart
                                data={threatHistory}
                                margin={{
                                    top: 10,
                                    right: 20,
                                    left: 0,
                                    bottom: 10
                                }}
                            >
                                <CartesianGrid
                                    strokeDasharray="3 3"
                                    stroke="#334155"
                                />

                                <XAxis
                                    dataKey="time"
                                    stroke="#94a3b8"
                                    tick={{
                                        fill: "#94a3b8",
                                        fontSize: 11
                                    }}
                                    tickFormatter={(value) =>
                                        new Date(
                                            value
                                        ).toLocaleTimeString(
                                            [],
                                            {
                                                hour: "2-digit",
                                                minute: "2-digit"
                                            }
                                        )
                                    }
                                />

                                <YAxis
                                    allowDecimals={false}
                                    stroke="#94a3b8"
                                    tick={{
                                        fill: "#94a3b8",
                                        fontSize: 11
                                    }}
                                />

                                <Tooltip
                                    labelFormatter={(value) =>
                                        new Date(
                                            value
                                        ).toLocaleString()
                                    }
                                    contentStyle={{
                                        backgroundColor:
                                            "#0f172a",
                                        border: "1px solid #334155",
                                        borderRadius: "8px",
                                        color: "#fff"
                                    }}
                                />

                                <Line
                                    type="monotone"
                                    dataKey="threats"
                                    name="Threats"
                                    stroke="#ef4444"
                                    strokeWidth={3}
                                    dot={{
                                        r: 3
                                    }}
                                    activeDot={{
                                        r: 5
                                    }}
                                />

                                <Line
                                    type="monotone"
                                    dataKey="failedLogins"
                                    name="Failed Logins"
                                    stroke="#eab308"
                                    strokeWidth={2}
                                    dot={{
                                        r: 3
                                    }}
                                />

                                <Line
                                    type="monotone"
                                    dataKey="unauthorized"
                                    name="Unauthorized"
                                    stroke="#3b82f6"
                                    strokeWidth={2}
                                    dot={{
                                        r: 3
                                    }}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="flex h-full items-center justify-center text-slate-500">
                            No security activity found for the selected period.
                        </div>
                    )}
                </div>

                <div className="mt-4 flex items-center justify-between border-t border-slate-800 pt-4">
                    <p className="text-xs text-slate-500">
                        PostgreSQL security history refreshes every 10 seconds.
                    </p>

                    <p className="text-xs text-green-400">
                        ● Live
                    </p>
                </div>
            </div>

            <div className="mt-8 grid gap-6 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                    <h3 className="text-lg font-semibold">
                        Threat Monitoring
                    </h3>

                    <div className="mt-6 space-y-5">
                        <MetricRow
                            label="Threats detected"
                            value={dashboard.totalThreats}
                            valueClass="text-red-400"
                        />

                        <MetricRow
                            label="Auto-blocked IPs"
                            value={dashboard.autoBlockedIPs}
                            valueClass="text-orange-400"
                        />

                        <MetricRow
                            label="Active blocked IPs"
                            value={dashboard.blockedIPs}
                            valueClass="text-yellow-400"
                        />
                    </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                    <h3 className="text-lg font-semibold">
                        Access Monitoring
                    </h3>

                    <div className="mt-6 space-y-5">
                        <MetricRow
                            label="Failed logins"
                            value={dashboard.failedLogins}
                            valueClass="text-yellow-400"
                        />

                        <MetricRow
                            label="Unauthorized access"
                            value={dashboard.unauthorizedAccess}
                            valueClass="text-orange-400"
                        />

                        <MetricRow
                            label="Rate-limit violations"
                            value={dashboard.rateLimitViolations}
                            valueClass="text-blue-400"
                        />
                    </div>
                </div>
            </div>

            <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900 p-6">
                <h3 className="text-lg font-semibold">
                    Gateway Performance
                </h3>

                <div className="mt-5">
                    <div className="flex justify-between">
                        <span className="text-slate-400">
                            Average API response time
                        </span>

                        <span className="font-bold text-blue-400">
                            {dashboard.averageResponseTime} ms
                        </span>
                    </div>

                    <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-800">
                        <div
                            className="h-full rounded-full bg-blue-600"
                            style={{
                                width: `${Math.min(
                                    Number(
                                        dashboard.averageResponseTime ||
                                            0
                                    ),
                                    100
                                )}%`
                            }}
                        ></div>
                    </div>
                </div>
            </div>
        </>
    );
}

function MetricRow({
    label,
    value,
    valueClass = "text-white"
}) {
    return (
        <div className="flex items-center justify-between">
            <span className="text-slate-400">
                {label}
            </span>

            <span
                className={`font-bold ${valueClass}`}
            >
                {value}
            </span>
        </div>
    );
}

function EventsPage({ events }) {
    return (
        <div className="rounded-xl border border-slate-800 bg-slate-900">
            <div className="border-b border-slate-800 p-6">
                <h3 className="text-lg font-semibold">
                    Security Events
                </h3>

                <p className="mt-1 text-sm text-slate-400">
                    Security activity recorded by the gateway
                </p>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-slate-400">
                        <tr>
                            <th className="px-6 py-4">
                                Event
                            </th>

                            <th className="px-6 py-4">
                                Method
                            </th>

                            <th className="px-6 py-4">
                                URL
                            </th>

                            <th className="px-6 py-4">
                                IP
                            </th>

                            <th className="px-6 py-4">
                                User
                            </th>

                            <th className="px-6 py-4">
                                Details
                            </th>

                            <th className="px-6 py-4">
                                Time
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        {events.map((event) => (
                            <tr
                                key={event.id}
                                className="border-b border-slate-800 hover:bg-slate-800/50"
                            >
                                <td className="px-6 py-4">
                                    <span className="rounded-full bg-red-950 px-3 py-1 text-xs text-red-400">
                                        {event.event}
                                    </span>
                                </td>

                                <td className="px-6 py-4 text-slate-300">
                                    {event.method || "-"}
                                </td>

                                <td className="max-w-xs truncate px-6 py-4 text-slate-400">
                                    {event.url || "-"}
                                </td>

                                <td className="px-6 py-4 font-mono text-slate-300">
                                    {event.ip || "-"}
                                </td>

                                <td className="px-6 py-4 text-slate-300">
                                    {event.username || "-"}
                                </td>

                                <td
                                    className="max-w-sm truncate px-6 py-4 text-slate-400"
                                    title={event.details || ""}
                                >
                                    {event.details || "-"}
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-slate-500">
                                    {event.created_at
                                        ? new Date(
                                              event.created_at
                                          ).toLocaleString()
                                        : "-"}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {events.length === 0 && (
                    <div className="p-10 text-center text-slate-500">
                        No security events found.
                    </div>
                )}
            </div>
        </div>
    );
}

function RequestsPage({ requests }) {
    return (
        <div className="rounded-xl border border-slate-800 bg-slate-900">
            <div className="border-b border-slate-800 p-6">
                <h3 className="text-lg font-semibold">
                    API Request Monitoring
                </h3>

                <p className="mt-1 text-sm text-slate-400">
                    Requests processed through the gateway
                </p>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-slate-400">
                        <tr>
                            <th className="px-6 py-4">
                                Method
                            </th>

                            <th className="px-6 py-4">
                                URL
                            </th>

                            <th className="px-6 py-4">
                                IP
                            </th>

                            <th className="px-6 py-4">
                                User
                            </th>

                            <th className="px-6 py-4">
                                Status
                            </th>

                            <th className="px-6 py-4">
                                Response Time
                            </th>

                            <th className="px-6 py-4">
                                Time
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        {requests.map((request) => (
                            <tr
                                key={request.id}
                                className="border-b border-slate-800 hover:bg-slate-800/50"
                            >
                                <td className="px-6 py-4 font-semibold text-blue-400">
                                    {request.method}
                                </td>

                                <td
                                    className="max-w-xs truncate px-6 py-4 text-slate-300"
                                    title={request.url || ""}
                                >
                                    {request.url}
                                </td>

                                <td className="px-6 py-4 font-mono text-slate-400">
                                    {request.ip}
                                </td>

                                <td className="px-6 py-4 text-slate-300">
                                    {request.username || "-"}
                                </td>

                                <td className="px-6 py-4">
                                    <span
                                        className={`rounded-full px-3 py-1 text-xs ${
                                            Number(
                                                request.status_code
                                            ) >= 400
                                                ? "bg-red-950 text-red-400"
                                                : "bg-green-950 text-green-400"
                                        }`}
                                    >
                                        {request.status_code}
                                    </span>
                                </td>

                                <td className="px-6 py-4 text-slate-300">
                                    {request.response_time_ms} ms
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-slate-500">
                                    {request.created_at
                                        ? new Date(
                                              request.created_at
                                          ).toLocaleString()
                                        : "-"}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {requests.length === 0 && (
                    <div className="p-10 text-center text-slate-500">
                        No API requests found.
                    </div>
                )}
            </div>
        </div>
    );
}

function BlockedIPsPage({
    blockedIPs,
    showBlockForm,
    setShowBlockForm,
    blockForm,
    setBlockForm,
    blockIP,
    unblockIP
}) {
    return (
        <div>
            <div className="mb-6 flex items-center justify-between">
                <div>
                    <h3 className="text-xl font-semibold">
                        Blocked IP Management
                    </h3>

                    <p className="mt-1 text-sm text-slate-400">
                        Manage IP addresses blocked by the gateway
                    </p>
                </div>

                <button
                    onClick={() =>
                        setShowBlockForm(!showBlockForm)
                    }
                    className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium hover:bg-red-500"
                >
                    {showBlockForm ? "Cancel" : "Block IP"}
                </button>
            </div>

            {showBlockForm && (
                <form
                    onSubmit={blockIP}
                    className="mb-6 rounded-xl border border-slate-800 bg-slate-900 p-6"
                >
                    <h4 className="mb-5 text-lg font-semibold">
                        Block IP Address
                    </h4>

                    <div className="grid gap-4 md:grid-cols-3">
                        <div>
                            <label className="mb-2 block text-xs text-slate-400">
                                IP Address
                            </label>

                            <input
                                type="text"
                                placeholder="127.0.0.1"
                                value={blockForm.ip}
                                onChange={(event) =>
                                    setBlockForm({
                                        ...blockForm,
                                        ip: event.target.value
                                    })
                                }
                                required
                                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-blue-500"
                            />
                        </div>

                        <div>
                            <label className="mb-2 block text-xs text-slate-400">
                                Reason
                            </label>

                            <input
                                type="text"
                                placeholder="Suspicious activity"
                                value={blockForm.reason}
                                onChange={(event) =>
                                    setBlockForm({
                                        ...blockForm,
                                        reason: event.target.value
                                    })
                                }
                                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-blue-500"
                            />
                        </div>

                        <div>
                            <label className="mb-2 block text-xs text-slate-400">
                                Expiration
                            </label>

                            <input
                                type="number"
                                min="1"
                                placeholder="Minutes"
                                value={blockForm.expiresInMinutes}
                                onChange={(event) =>
                                    setBlockForm({
                                        ...blockForm,
                                        expiresInMinutes:
                                            event.target.value
                                    })
                                }
                                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-blue-500"
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="mt-5 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-medium hover:bg-blue-500"
                    >
                        Block IP Address
                    </button>
                </form>
            )}

            <div className="rounded-xl border border-slate-800 bg-slate-900">
                <div className="border-b border-slate-800 p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <h4 className="text-lg font-semibold">
                                Active Block Records
                            </h4>

                            <p className="mt-1 text-sm text-slate-500">
                                Currently active IP restrictions
                            </p>
                        </div>

                        <span className="rounded-full bg-red-950 px-3 py-1 text-xs text-red-400">
                            {blockedIPs.length} Active
                        </span>
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                        <thead className="border-b border-slate-800 text-slate-400">
                            <tr>
                                <th className="px-6 py-4">
                                    IP Address
                                </th>

                                <th className="px-6 py-4">
                                    Reason
                                </th>

                                <th className="px-6 py-4">
                                    Blocked At
                                </th>

                                <th className="px-6 py-4">
                                    Expires At
                                </th>

                                <th className="px-6 py-4">
                                    Action
                                </th>
                            </tr>
                        </thead>

                        <tbody>
                            {blockedIPs.map((item) => (
                                <tr
                                    key={item.id}
                                    className="border-b border-slate-800 hover:bg-slate-800/50"
                                >
                                    <td className="px-6 py-4 font-mono text-red-400">
                                        {item.entity_value}
                                    </td>

                                    <td
                                        className="max-w-sm truncate px-6 py-4 text-slate-300"
                                        title={item.reason || ""}
                                    >
                                        {item.reason}
                                    </td>

                                    <td className="whitespace-nowrap px-6 py-4 text-slate-400">
                                        {item.blocked_at
                                            ? new Date(
                                                  item.blocked_at
                                              ).toLocaleString()
                                            : "-"}
                                    </td>

                                    <td className="whitespace-nowrap px-6 py-4 text-slate-400">
                                        {item.expires_at
                                            ? new Date(
                                                  item.expires_at
                                              ).toLocaleString()
                                            : "Permanent"}
                                    </td>

                                    <td className="px-6 py-4">
                                        <button
                                            onClick={() =>
                                                unblockIP(
                                                    item.entity_value
                                                )
                                            }
                                            className="rounded-lg bg-green-700 px-3 py-2 text-xs font-medium hover:bg-green-600"
                                        >
                                            Unblock
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>

                    {blockedIPs.length === 0 && (
                        <div className="p-10 text-center">
                            <div className="text-3xl">
                                ✓
                            </div>

                            <p className="mt-3 text-slate-400">
                                No active blocked IPs.
                            </p>

                            <p className="mt-1 text-xs text-slate-600">
                                The gateway currently has no active IP restrictions.
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default App;