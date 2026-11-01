// auth.js
// SABE Account System — Client Auth Module

const SABE_API = "https://sabeauth.brsokksellw.workers.dev/";

const SESSION_KEY = "sabe_session_token";

let preAuthToken = null;

// -----------------------------
// API REQUEST
// -----------------------------

async function request(path, options = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    const token = sessionStorage.getItem(SESSION_KEY);

    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(`${SABE_API}${path}`, {
        ...options,
        headers
    });

    let result;

    try {
        result = await response.json();
    } catch {
        throw new Error("INVALID_SERVER_RESPONSE");
    }

    if (!response.ok) {
        throw new Error(result.error || "REQUEST_FAILED");
    }

    return result;
}

// -----------------------------
// STEP 1 — TELEGRAM AUTH
// -----------------------------

export async function startTelegramAuth() {
    const telegram = window.Telegram?.WebApp;

    if (!telegram || !telegram.initData) {
        throw new Error("TELEGRAM_REQUIRED");
    }

    telegram.ready();

    const result = await request("/api/auth/telegram", {
        method: "POST",
        body: JSON.stringify({
            initData: telegram.initData
        })
    });

    preAuthToken = result.preAuthToken;

    return {
        passwordRequired: result.passwordRequired,
        passwordSetupRequired: result.passwordSetupRequired
    };
}

// -----------------------------
// STEP 2A — SET PASSWORD
// -----------------------------

export async function setupPassword(password) {
    validatePassword(password);

    if (!preAuthToken) {
        throw new Error("PREAUTH_REQUIRED");
    }

    const result = await request("/api/auth/password/setup", {
        method: "POST",
        headers: {
            "X-Preauth-Token": preAuthToken
        },
        body: JSON.stringify({ password })
    });

    saveSession(result);
    preAuthToken = null;

    return result.user;
}

// -----------------------------
// STEP 2B — VERIFY PASSWORD
// -----------------------------

export async function loginWithPassword(password) {
    if (!preAuthToken) {
        throw new Error("PREAUTH_REQUIRED");
    }

    if (typeof password !== "string" || !password) {
        throw new Error("PASSWORD_REQUIRED");
    }

    const result = await request("/api/auth/password/verify", {
        method: "POST",
        headers: {
            "X-Preauth-Token": preAuthToken
        },
        body: JSON.stringify({ password })
    });

    saveSession(result);
    preAuthToken = null;

    return result.user;
}

// -----------------------------
// SESSION
// -----------------------------

function saveSession(result) {
    if (!result.token || !result.expiresAt) {
        throw new Error("INVALID_SESSION_RESPONSE");
    }

    sessionStorage.setItem(SESSION_KEY, result.token);
    sessionStorage.setItem(
        "sabe_session_expires",
        String(result.expiresAt)
    );
}

export function hasSession() {
    const token = sessionStorage.getItem(SESSION_KEY);
    const expiresAt = Number(
        sessionStorage.getItem("sabe_session_expires")
    );

    return Boolean(
        token &&
        Number.isFinite(expiresAt) &&
        expiresAt * 1000 > Date.now()
    );
}

export async function getMe() {
    if (!hasSession()) {
        throw new Error("UNAUTHORIZED");
    }

    return request("/api/me", {
        method: "GET"
    });
}

export async function logout() {
    try {
        if (hasSession()) {
            await request("/api/logout", {
                method: "POST"
            });
        }
    } finally {
        clearSession();
    }
}

export function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem("sabe_session_expires");
    preAuthToken = null;
}

// -----------------------------
// VALIDATION
// -----------------------------

function validatePassword(password) {
    if (typeof password !== "string") {
        throw new Error("INVALID_PASSWORD");
    }

    if (password.length < 10 || password.length > 128) {
        throw new Error("PASSWORD_LENGTH_INVALID");
    }
}
