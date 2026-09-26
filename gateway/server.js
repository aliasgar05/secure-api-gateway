require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const pool = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const THREAT_THRESHOLD = 3;
const THREAT_WINDOW_MINUTES = 10;
const AUTO_BLOCK_MINUTES = 10;

app.use(express.json({ limit: "1mb" }));

app.use(
    cors({
        origin: "http://localhost:5173",
        methods: ["GET", "POST", "DELETE", "PUT", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"]
    })
);

async function securityLog(event) {
    try {
        await pool.query(
            `INSERT INTO security_events
            (event, method, url, ip, username, details)
            VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                event.event,
                event.method,
                event.url,
                event.ip,
                event.username || "unknown",
                event.details || ""
            ]
        );

        console.log("SECURITY EVENT SAVED:", event.event);
    } catch (error) {
        console.error(
            "Security log database error:",
            error.message
        );
    }
}

async function autoBlockIP(ip, reason) {
    try {
        const result = await pool.query(
            `SELECT COUNT(*) AS threat_count
             FROM security_events
             WHERE event = 'THREAT_DETECTED'
             AND ip = $1
             AND created_at >= CURRENT_TIMESTAMP - INTERVAL '${THREAT_WINDOW_MINUTES} minutes'`,
            [ip]
        );

        const threatCount = Number(
            result.rows[0].threat_count
        );

        console.log(
            `Threat count for ${ip}: ${threatCount}`
        );

        if (threatCount >= THREAT_THRESHOLD) {
            const existingBlock = await pool.query(
                `SELECT id
                 FROM blocked_entities
                 WHERE entity_type = 'IP'
                 AND entity_value = $1
                 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
                [ip]
            );

            if (existingBlock.rows.length > 0) {
                return;
            }

            const expiresAt = new Date(
                Date.now() +
                AUTO_BLOCK_MINUTES * 60 * 1000
            );

            await pool.query(
                `INSERT INTO blocked_entities
                (entity_type, entity_value, reason, expires_at)
                VALUES ('IP', $1, $2, $3)
                ON CONFLICT (entity_value)
                DO UPDATE SET
                    reason = EXCLUDED.reason,
                    expires_at = EXCLUDED.expires_at`,
                [
                    ip,
                    reason ||
                        "Automatically blocked after repeated threats",
                    expiresAt
                ]
            );

            await securityLog({
                event: "IP_AUTO_BLOCKED",
                method: "SYSTEM",
                url: "THREAT_DETECTION",
                ip: ip,
                username: "system",
                details:
                    `IP automatically blocked after ${threatCount} threats`
            });

            console.log(
                `AUTO BLOCK: ${ip} blocked for ${AUTO_BLOCK_MINUTES} minutes`
            );
        }
    } catch (error) {
        console.error(
            "Automatic IP blocking error:",
            error.message
        );
    }
}

async function checkBlockedIP(req, res, next) {
    const managementRoutes = [
        req.path === "/security/dashboard",
        req.path === "/security/threat-history",
        req.path === "/security/blocked-ips",
        req.path === "/security/block-ip",
        req.path.startsWith("/security/block-ip/")
    ];

    if (managementRoutes.some(Boolean)) {
        return next();
    }

    try {
        const result = await pool.query(
            `SELECT id, reason, expires_at
             FROM blocked_entities
             WHERE entity_type = 'IP'
             AND entity_value = $1
             AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
            [req.ip]
        );

        if (result.rows.length > 0) {
            const blocked = result.rows[0];

            await securityLog({
                event: "BLOCKED_IP_REQUEST",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user
                    ? req.user.username
                    : "unknown",
                details:
                    blocked.reason ||
                    "IP address is blocked"
            });

            return res.status(403).json({
                error: "Access denied",
                reason: "Your IP address is blocked"
            });
        }

        next();
    } catch (error) {
        console.error(
            "Blocked IP check error:",
            error.message
        );

        next();
    }
}

app.use(checkBlockedIP);

app.use((req, res, next) => {
    const startTime = Date.now();

    res.on("finish", async () => {
        const responseTime = Date.now() - startTime;

        try {
            await pool.query(
                `INSERT INTO api_requests
                (method, url, ip, username, status_code, response_time_ms)
                VALUES ($1, $2, $3, $4, $5, $6)`,
                [
                    req.method,
                    req.originalUrl,
                    req.ip,
                    req.user
                        ? req.user.username
                        : "unknown",
                    res.statusCode,
                    responseTime
                ]
            );
        } catch (error) {
            console.error(
                "API request logging error:",
                error.message
            );
        }
    });

    next();
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many requests, please try again later"
    },
    handler: (req, res) => {
        securityLog({
            event: "RATE_LIMIT_EXCEEDED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: req.user
                ? req.user.username
                : "unknown",
            details: "Rate limit exceeded"
        });

        res.status(429).json({
            error: "Too many requests, please try again later"
        });
    }
});

app.get("/", (req, res) => {
    res.json({
        message: "Secure API Gateway is running"
    });
});

app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        securityLog({
            event: "LOGIN_FAILED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: username || "unknown",
            details: "Username or password missing"
        });

        return res.status(400).json({
            error: "Username and password are required"
        });
    }

    try {
        const result = await pool.query(
            `SELECT id, username, password_hash, role
             FROM users
             WHERE username = $1`,
            [username]
        );

        if (result.rows.length === 0) {
            securityLog({
                event: "LOGIN_FAILED",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username,
                details: "Invalid username or password"
            });

            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const user = result.rows[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            securityLog({
                event: "LOGIN_FAILED",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username,
                details: "Invalid username or password"
            });

            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        await securityLog({
            event: "LOGIN_SUCCESS",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: user.username,
            details: "User authenticated successfully"
        });

        const token = jwt.sign(
            {
                userId: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        res.json({
            message: "Login successful",
            token: token
        });
    } catch (error) {
        console.error(
            "Login database error:",
            error.message
        );

        securityLog({
            event: "LOGIN_ERROR",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: username || "unknown",
            details: "Database error during authentication"
        });

        res.status(500).json({
            error: "Authentication service error"
        });
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        securityLog({
            event: "AUTHENTICATION_FAILED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: "unknown",
            details: "Authentication token missing"
        });

        return res.status(401).json({
            error: "Authentication token required"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.user = decoded;
        next();
    } catch (error) {
        securityLog({
            event: "AUTHENTICATION_FAILED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: "unknown",
            details: "Invalid or expired token"
        });

        return res.status(401).json({
            error: "Invalid or expired token"
        });
    }
}

function authorizeRole(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            securityLog({
                event: "UNAUTHORIZED_ACCESS",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user.username,
                details:
                    `Required role: ${allowedRoles.join(", ")}`
            });

            return res.status(403).json({
                error: "Access denied"
            });
        }

        next();
    };
}

function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        securityLog({
            event: "VALIDATION_FAILED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: req.user
                ? req.user.username
                : "unknown",
            details: JSON.stringify(errors.array())
        });

        return res.status(400).json({
            error: "Invalid request",
            details: errors.array()
        });
    }

    next();
}

async function threatDetection(req, res, next) {
    const input = JSON.stringify({
        url: req.originalUrl,
        body: req.body,
        query: req.query
    }).toLowerCase();

    const suspiciousPatterns = [
        "union select",
        "drop table",
        "delete from",
        "insert into",
        "or 1=1",
        "<script",
        "javascript:",
        "../",
        "..\\",
        "cmd.exe",
        "powershell",
        "/etc/passwd"
    ];

    const detectedPattern =
        suspiciousPatterns.find(pattern =>
            input.includes(pattern)
        );

    if (detectedPattern) {
        const threatDetails =
            `Suspicious pattern detected: ${detectedPattern}`;

        await securityLog({
            event: "THREAT_DETECTED",
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            username: req.user
                ? req.user.username
                : "unknown",
            details: threatDetails
        });

        await autoBlockIP(
            req.ip,
            `Automatic block: repeated threat detected - ${detectedPattern}`
        );

        return res.status(403).json({
            error: "Suspicious request blocked",
            reason: "Potential malicious input detected"
        });
    }

    next();
}

app.get(
    "/api/users",
    apiLimiter,
    authenticateToken,
    authorizeRole("Admin"),
    threatDetection,
    async (req, res) => {
        try {
            const response = await fetch(
                "http://localhost:4000/api/users"
            );

            const data = await response.json();

            res.status(response.status).json(data);
        } catch (error) {
            securityLog({
                event: "BACKEND_ERROR",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user
                    ? req.user.username
                    : "unknown",
                details: "Backend service unavailable"
            });

            res.status(503).json({
                error: "Backend service unavailable"
            });
        }
    }
);

app.get(
    "/api/data",
    apiLimiter,
    authenticateToken,
    threatDetection,
    async (req, res) => {
        try {
            const response = await fetch(
                "http://localhost:4000/api/data"
            );

            const data = await response.json();

            res.status(response.status).json(data);
        } catch (error) {
            securityLog({
                event: "BACKEND_ERROR",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user
                    ? req.user.username
                    : "unknown",
                details: "Backend service unavailable"
            });

            res.status(503).json({
                error: "Backend service unavailable"
            });
        }
    }
);

app.post(
    "/api/data",
    apiLimiter,
    authenticateToken,
    [
        body("name")
            .trim()
            .notEmpty()
            .withMessage("Name is required")
            .isLength({ max: 100 })
            .withMessage(
                "Name must not exceed 100 characters"
            ),

        body("quantity")
            .isInt({
                min: 1,
                max: 100000
            })
            .withMessage(
                "Quantity must be a valid positive integer"
            )
    ],
    handleValidationErrors,
    threatDetection,
    async (req, res) => {
        try {
            const response = await fetch(
                "http://localhost:4000/api/data",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(req.body)
                }
            );

            const data = await response.json();

            res.status(response.status).json(data);
        } catch (error) {
            securityLog({
                event: "BACKEND_ERROR",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user
                    ? req.user.username
                    : "unknown",
                details: "Backend service unavailable"
            });

            res.status(503).json({
                error: "Backend service unavailable"
            });
        }
    }
);

app.get(
    "/security/events",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT
                    id,
                    event,
                    method,
                    url,
                    ip,
                    username,
                    details,
                    created_at
                 FROM security_events
                 ORDER BY created_at DESC`
            );

            res.json({
                totalEvents: result.rows.length,
                events: result.rows
            });
        } catch (error) {
            console.error(
                "Failed to retrieve security events:",
                error.message
            );

            res.status(500).json({
                error: "Failed to retrieve security events"
            });
        }
    }
);

app.get(
    "/api/requests",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT
                    id,
                    method,
                    url,
                    ip,
                    username,
                    status_code,
                    response_time_ms,
                    created_at
                 FROM api_requests
                 ORDER BY created_at DESC`
            );

            res.json({
                totalRequests: result.rows.length,
                requests: result.rows
            });
        } catch (error) {
            console.error(
                "Failed to retrieve API requests:",
                error.message
            );

            res.status(500).json({
                error: "Failed to retrieve API requests"
            });
        }
    }
);

app.post(
    "/security/block-ip",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        const {
            ip,
            reason,
            expiresInMinutes
        } = req.body;

        if (!ip) {
            return res.status(400).json({
                error: "IP address is required"
            });
        }

        try {
            let expiresAt = null;

            if (
                expiresInMinutes !== undefined &&
                expiresInMinutes !== null
            ) {
                const minutes = Number(
                    expiresInMinutes
                );

                if (
                    !Number.isFinite(minutes) ||
                    minutes <= 0
                ) {
                    return res.status(400).json({
                        error:
                            "expiresInMinutes must be a positive number"
                    });
                }

                expiresAt = new Date(
                    Date.now() +
                    minutes * 60 * 1000
                );
            }

            await pool.query(
                `INSERT INTO blocked_entities
                (entity_type, entity_value, reason, expires_at)
                VALUES ('IP', $1, $2, $3)
                ON CONFLICT (entity_value)
                DO UPDATE SET
                    reason = EXCLUDED.reason,
                    expires_at = EXCLUDED.expires_at`,
                [
                    ip,
                    reason ||
                        "Blocked by administrator",
                    expiresAt
                ]
            );

            await securityLog({
                event: "IP_BLOCKED",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user.username,
                details:
                    `Blocked IP: ${ip}`
            });

            res.json({
                message:
                    "IP address blocked successfully",
                ip: ip,
                expiresAt: expiresAt
            });
        } catch (error) {
            console.error(
                "IP blocking error:",
                error.message
            );

            res.status(500).json({
                error:
                    "Failed to block IP address"
            });
        }
    }
);

app.delete(
    "/security/block-ip/:ip",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        const ip = req.params.ip;

        try {
            const result = await pool.query(
                `DELETE FROM blocked_entities
                 WHERE entity_type = 'IP'
                 AND entity_value = $1
                 RETURNING *`,
                [ip]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error:
                        "IP address is not blocked"
                });
            }

            await securityLog({
                event: "IP_UNBLOCKED",
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                username: req.user.username,
                details:
                    `Unblocked IP: ${ip}`
            });

            res.json({
                message:
                    "IP address unblocked successfully",
                ip: ip
            });
        } catch (error) {
            console.error(
                "IP unblocking error:",
                error.message
            );

            res.status(500).json({
                error:
                    "Failed to unblock IP address"
            });
        }
    }
);

app.get(
    "/security/blocked-ips",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT
                    id,
                    entity_type,
                    entity_value,
                    reason,
                    blocked_at,
                    expires_at
                 FROM blocked_entities
                 WHERE entity_type = 'IP'
                 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                 ORDER BY blocked_at DESC`
            );

            res.json({
                totalBlocked: result.rows.length,
                blockedIPs: result.rows
            });
        } catch (error) {
            console.error(
                "Failed to retrieve blocked IPs:",
                error.message
            );

            res.status(500).json({
                error:
                    "Failed to retrieve blocked IPs"
            });
        }
    }
);

app.get(
    "/security/dashboard",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        try {
            const requestsResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM api_requests`
            );

            const threatsResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM security_events
                 WHERE event = 'THREAT_DETECTED'`
            );

            const failedLoginsResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM security_events
                 WHERE event = 'LOGIN_FAILED'`
            );

            const blockedIPsResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM blocked_entities
                 WHERE entity_type = 'IP'
                 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
            );

            const rateLimitResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM security_events
                 WHERE event = 'RATE_LIMIT_EXCEEDED'`
            );

            const unauthorizedResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM security_events
                 WHERE event = 'UNAUTHORIZED_ACCESS'`
            );

            const autoBlockedResult = await pool.query(
                `SELECT COUNT(*) AS total
                 FROM security_events
                 WHERE event = 'IP_AUTO_BLOCKED'`
            );

            const responseTimeResult = await pool.query(
                `SELECT COALESCE(
                    ROUND(AVG(response_time_ms), 2),
                    0
                 ) AS average
                 FROM api_requests`
            );

            res.json({
                totalRequests: Number(
                    requestsResult.rows[0].total
                ),
                totalThreats: Number(
                    threatsResult.rows[0].total
                ),
                failedLogins: Number(
                    failedLoginsResult.rows[0].total
                ),
                blockedIPs: Number(
                    blockedIPsResult.rows[0].total
                ),
                rateLimitViolations: Number(
                    rateLimitResult.rows[0].total
                ),
                unauthorizedAccess: Number(
                    unauthorizedResult.rows[0].total
                ),
                autoBlockedIPs: Number(
                    autoBlockedResult.rows[0].total
                ),
                averageResponseTime: Number(
                    responseTimeResult.rows[0].average
                )
            });
        } catch (error) {
            console.error(
                "Dashboard statistics error:",
                error.message
            );

            res.status(500).json({
                error: "Failed to load dashboard statistics"
            });
        }
    }
);

app.get(
    "/security/threat-history",
    authenticateToken,
    authorizeRole("Admin"),
    async (req, res) => {
        try {
            const requestedMinutes = Number(
                req.query.minutes
            );

            const minutes =
                Number.isFinite(requestedMinutes) &&
                requestedMinutes >= 10
                    ? Math.min(requestedMinutes, 1440)
                    : 60;

            const result = await pool.query(
                `
                WITH time_buckets AS (
                    SELECT generate_series(
                        date_trunc(
                            'minute',
                            CURRENT_TIMESTAMP -
                            ($1 * INTERVAL '1 minute')
                        ),
                        date_trunc(
                            'minute',
                            CURRENT_TIMESTAMP
                        ),
                        INTERVAL '1 minute'
                    ) AS time
                )
                SELECT
                    tb.time,

                    COUNT(se.id) FILTER (
                        WHERE se.event = 'THREAT_DETECTED'
                    ) AS threats,

                    COUNT(se.id) FILTER (
                        WHERE se.event = 'LOGIN_FAILED'
                    ) AS failed_logins,

                    COUNT(se.id) FILTER (
                        WHERE se.event = 'UNAUTHORIZED_ACCESS'
                    ) AS unauthorized

                FROM time_buckets tb

                LEFT JOIN security_events se
                    ON se.created_at >= tb.time
                    AND se.created_at <
                        tb.time + INTERVAL '1 minute'

                GROUP BY tb.time
                ORDER BY tb.time ASC
                `,
                [minutes]
            );

            const history = result.rows.map(row => ({
                time: new Date(row.time).toLocaleTimeString(
                    [],
                    {
                        hour: "2-digit",
                        minute: "2-digit"
                    }
                ),
                threats: Number(row.threats),
                failedLogins: Number(row.failed_logins),
                unauthorized: Number(row.unauthorized)
            }));

            res.json({
                minutes,
                history
            });
        } catch (error) {
            console.error(
                "Threat history error:",
                error.message
            );

            res.status(500).json({
                error: "Failed to load threat history"
            });
        }
    }
);

app.use((req, res) => {
    securityLog({
        event: "RESOURCE_NOT_FOUND",
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        username: req.user
            ? req.user.username
            : "unknown",
        details:
            "Requested resource does not exist"
    });

    res.status(404).json({
        error: "Resource not found"
    });
});

app.use((err, req, res, next) => {
    securityLog({
        event: "INTERNAL_SERVER_ERROR",
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        username: req.user
            ? req.user.username
            : "unknown",
        details: err.message
    });

    console.error(err);

    res.status(500).json({
        error: "Internal server error"
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`API Gateway running on port ${PORT}`);
});