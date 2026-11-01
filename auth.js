
// SABE Account System — Auth Client v2.1

const SABE_API = "https://sabeauth.brsokksellw.workers.dev";

const SESSION_KEY = "sabe_session_token";
const EXPIRES_KEY = "sabe_session_expires";

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

    if (token && !headers.Authorization) {
        headers.Authorization = `Bearer ${token}`;
    }

    let response;

    try {
        response = await fetch(`${SABE_API}${path}`, {
            ...options,
            headers
        });
    } catch (error) {
        console.error("[SABE] Network error:", error);
        throw new Error("NETWORK_ERROR");
    }

    let result;

    try {
        result = await response.json();
    } catch {
        throw new Error("INVALID_SERVER_RESPONSE");
    }

    if (!response.ok) {
        const error = new Error(
            result.error || `HTTP_${response.status}`
        );

        error.status = response.status;
        error.details = result;

        console.error("[SABE] API error:", {
            path,
            status: response.status,
            error: result.error
        });

        throw error;
    }

    return result;
}

// -----------------------------
// TELEGRAM AUTH
// -----------------------------

export async function startTelegramAuth() {
    const telegram = window.Telegram?.WebApp;

    if (!telegram) {
        throw new Error("TELEGRAM_REQUIRED");
    }

    telegram.ready();

    const initData = telegram.initData;

    if (typeof initData !== "string" || initData.length === 0) {
        throw new Error("TELEGRAM_INITDATA_MISSING");
    }

    console.info("[SABE] Telegram Mini App detected");
    console.info("[SABE] initData length:", initData.length);
    console.info("[SABE] Platform:", telegram.platform || "unknown");

    const result = await request("/api/auth/telegram", {
        method: "POST",
        body: JSON.stringify({ initData })
    });

    if (!result.preAuthToken) {
        throw new Error("PREAUTH_TOKEN_MISSING");
    }

    preAuthToken = result.preAuthToken;

    return {
        passwordRequired: Boolean(result.passwordRequired),
        passwordSetupRequired: Boolean(result.passwordSetupRequired)
    };
}

// -----------------------------
// PASSWORD SETUP
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
// PASSWORD LOGIN
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
    if (!result?.token || !result?.expiresAt) {
        throw new Error("INVALID_SESSION_RESPONSE");
    }

    sessionStorage.setItem(SESSION_KEY, result.token);
    sessionStorage.setItem(
        EXPIRES_KEY,
        String(result.expiresAt)
    );
}

export function hasSession() {
    try {
        const token = sessionStorage.getItem(SESSION_KEY);
        const expiresAt = Number(
            sessionStorage.getItem(EXPIRES_KEY)
        );

        return Boolean(
            token &&
            Number.isFinite(expiresAt) &&
            expiresAt * 1000 > Date.now()
        );
    } catch {
        return false;
    }
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
    sessionStorage.removeItem(EXPIRES_KEY);
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

// -----------------------------
// DIAGNOSTICS
// -----------------------------

export function getAuthDiagnostics() {
    const telegram = window.Telegram?.WebApp;

    return {
        telegramAvailable: Boolean(telegram),
        initDataAvailable: Boolean(telegram?.initData),
        initDataLength: telegram?.initData?.length || 0,
        platform: telegram?.platform || null,
        sessionAvailable: hasSession(),
        api: SABE_API
    };
}

