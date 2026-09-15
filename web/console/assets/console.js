// Shared admin console helpers. TSI framework standard pattern (matches
// tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault): every call is POST to a fixed
// resource path with "_func" + params in the JSON body - no REST verbs, no
// {id} path segments. No build step, plain fetch + DOM.
//
// Console sessions are a JWT (matches tsi-compass), stored in localStorage
// and sent as "Authorization: Bearer <token>" - not a session cookie - so
// the session survives a server restart (the token carries the session,
// the server holds no state for it).

function getAuthToken() {
    try {
        return localStorage.getItem("token");
    } catch (e) {
        return null;
    }
}

function setAuthToken(token) {
    try {
        localStorage.setItem("token", token);
    } catch (e) { /* private-browsing storage denial - session just won't persist across reloads */ }
}

function clearAuthToken() {
    try {
        localStorage.removeItem("token");
    } catch (e) { }
}

async function apiFetch(path, options, skipAuthRedirect) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options && options.headers);
    const token = getAuthToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(path, Object.assign({}, options, { headers }));
    if (res.status === 401 && !skipAuthRedirect) {
        clearAuthToken();
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

/** Display-only role labels - the API/DB keep the raw enum values. */
const ROLE_LABELS = { PLATFORM_ADMIN: "Admin", APP_MANAGER: "App Manager", AUDITOR: "Auditor" };
function roleLabel(role) {
    return ROLE_LABELS[role] || role;
}

/* ---------- Shared modal open/close (any page with a .modal-overlay) ---------- */

function openModal(id) { document.getElementById(id).classList.add("open"); }
function closeModal(id) { document.getElementById(id).classList.remove("open"); }

async function copyText(text, btn) {
    try {
        await navigator.clipboard.writeText(text);
    } catch (e) {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
    }
    if (btn) {
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1200);
    }
}

async function loadTopbar() {
    const nameEl = document.getElementById("sidebar-user-name");
    const roleEl = document.getElementById("sidebar-user-role");
    const avatarEl = document.getElementById("sidebar-user-avatar");
    if (!nameEl) return;
    try {
        const me = await tsiCall("/api/v1/admin/auth", "me", {}, true);
        nameEl.textContent = me.fullName;
        if (roleEl) roleEl.textContent = roleLabel(me.role);
        if (avatarEl) {
            const initials = (me.fullName || "").trim().split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
            avatarEl.textContent = initials || "U";
        }
        // Admin-only nav items (Users & Roles, §10.9) - the backend still
        // enforces this; hiding the link just avoids showing a page that
        // would immediately 403.
        document.querySelectorAll(".platform-admin-only").forEach(node => {
            node.style.display = me.role === "PLATFORM_ADMIN" ? "" : "none";
        });
    } catch (e) {
        window.location.href = "login.html";
    }
}

async function logout() {
    try {
        await tsiCall("/api/v1/admin/auth", "logout", {}, true);
    } finally {
        clearAuthToken();
        window.location.href = "login.html";
    }
}

/* ---------- Shared pagination (page/pageSize/totalCount/totalPages response shape) ---------- */

/** Renders "Showing X-Y of Z" + Prev/Next into infoId/btnsId; loadFn(page) is called to fetch a page. */
function renderPagination(result, infoId, btnsId, noun, loadFn) {
    const infoEl = document.getElementById(infoId);
    const btnsEl = document.getElementById(btnsId);
    if (!infoEl || !btnsEl) return;
    const total = result.totalCount || 0;
    const page = result.page || 1;
    const pageSize = result.pageSize || 20;
    const totalPages = result.totalPages || 1;
    const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
    const to = Math.min(page * pageSize, total);
    infoEl.textContent = total === 0 ? `No ${noun}s.` : `Showing ${from}–${to} of ${total} ${noun}${total !== 1 ? "s" : ""}`;

    if (totalPages <= 1) {
        btnsEl.innerHTML = "";
        return;
    }
    let html = `<button class="secondary small" ${page <= 1 ? "disabled" : ""} data-page="${page - 1}">Prev</button>`;
    html += ` <span class="muted" style="margin:0 8px;">Page ${page} of ${totalPages}</span> `;
    html += `<button class="secondary small" ${page >= totalPages ? "disabled" : ""} data-page="${page + 1}">Next</button>`;
    btnsEl.innerHTML = html;
    btnsEl.querySelectorAll("[data-page]").forEach(btn => {
        btn.addEventListener("click", () => loadFn(parseInt(btn.dataset.page, 10)));
    });
}
