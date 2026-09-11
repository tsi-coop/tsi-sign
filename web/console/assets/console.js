// Shared admin console helpers. TSI framework standard pattern (matches
// tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault): every call is POST to a fixed
// resource path with "_func" + params in the JSON body — no REST verbs, no
// {id} path segments. No build step, plain fetch + DOM.

async function apiFetch(path, options, skipAuthRedirect) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
    if (res.status === 401 && !skipAuthRedirect) {
        window.location.href = "login.html";
        throw new Error("Not logged in");
    }
    return res;
}

async function apiJson(path, options, skipAuthRedirect) {
    const res = await apiFetch(path, options, skipAuthRedirect);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
        const err = new Error(body.message || res.statusText);
        err.status = res.status;
        err.body = body;
        throw err;
    }
    return body;
}

/** POST resourcePath with {_func, ...params} and parse the JSON response. */
async function tsiCall(resourcePath, func, params, skipAuthRedirect) {
    return apiJson(resourcePath, {
        method: "POST",
        body: JSON.stringify(Object.assign({ _func: func }, params || {}))
    }, skipAuthRedirect);
}

/** Same as tsiCall, but for funcs that return a binary (PDF) body. */
async function tsiCallBlob(resourcePath, func, params) {
    const res = await apiFetch(resourcePath, {
        method: "POST",
        body: JSON.stringify(Object.assign({ _func: func }, params || {}))
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message || res.statusText);
    }
    return res.blob();
}

/** Opens a blob-returning func's result in a new tab (preview/download). */
async function tsiOpenBlob(resourcePath, func, params) {
    const blob = await tsiCallBlob(resourcePath, func, params);
    window.open(URL.createObjectURL(blob), "_blank");
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
    const nameEl = document.getElementById("sidebar-user-name");
    const roleEl = document.getElementById("sidebar-user-role");
    const avatarEl = document.getElementById("sidebar-user-avatar");
    if (!nameEl) return;
    try {
        const me = await tsiCall("/api/v1/admin/auth", "me", {}, true);
        nameEl.textContent = me.fullName;
        if (roleEl) roleEl.textContent = me.role;
        if (avatarEl) {
            const initials = (me.fullName || "").trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
            avatarEl.textContent = initials || "U";
        }
        // Platform-admin-only nav items (Platform Users & Roles, §10.9) —
        // the backend still enforces this; hiding the link just avoids
        // showing a page that would immediately 403.
        document.querySelectorAll(".platform-admin-only").forEach(node => {
            node.style.display = me.role === "PLATFORM_ADMIN" ? "" : "none";
        });
    } catch (e) {
        window.location.href = "login.html";
    }
}

async function logout() {
    await tsiCall("/api/v1/admin/auth", "logout", {}, true);
    window.location.href = "login.html";
}
