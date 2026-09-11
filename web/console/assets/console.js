// Shared admin console helpers (Chunk 7). Plain fetch + DOM, no build step —
// matches the rest of TSI Sign's zero-external-dependency, self-hosted ethos.

async function apiFetch(path, options) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
    if (res.status === 401 && !path.includes("/auth/")) {
        window.location.href = "login.html";
        throw new Error("Not logged in");
    }
    return res;
}

async function apiJson(path, options) {
    const res = await apiFetch(path, options);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
        const err = new Error(body.message || res.statusText);
        err.status = res.status;
        err.body = body;
        throw err;
    }
    return body;
}

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function qs(name) {
    return new URLSearchParams(window.location.search).get(name);
}

function showNotice(el, message, type) {
    el.textContent = message;
    el.className = "notice " + (type || "error");
    el.style.display = message ? "block" : "none";
}

async function loadTopbar() {
    const el = document.getElementById("topbar-user");
    if (!el) return;
    try {
        const me = await apiJson("/api/v1/admin/auth/me");
        el.textContent = me.fullName + " (" + me.role + ")";
        // Platform-admin-only nav items (Platform Users & Roles, §10.9) —
        // the backend still enforces this; hiding the link just avoids
        // showing a page that would immediately 403.
        document.querySelectorAll(".platform-admin-only").forEach(node => {
            node.style.display = me.role === "PLATFORM_ADMIN" ? "" : "none";
        });
    } catch (e) {
        // ApiFetch already redirects to login on 401.
    }
}

async function logout() {
    await apiFetch("/api/v1/admin/auth/logout", { method: "POST" });
    window.location.href = "login.html";
}
