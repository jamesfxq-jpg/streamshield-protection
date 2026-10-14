/** Shared full/compact dashboard handlers. Data is written with textContent. */
export const quietShieldBrowserScript = String.raw`
const quietPendingActions = new Set();
function quietNotice(text, error = false) {
    const el = document.querySelector('#quietShieldNotice');
    if (!el) { alert(text); return; }
    el.textContent = String(text);
    el.className = 'small ' + (error ? 'warn' : '');
    el.hidden = false;
}
function quietButtons(userId, disabled) {
    for (const button of document.querySelectorAll?.('[data-quiet-user="' + userId + '"]') || []) button.disabled = disabled;
}
function quietBind(button, action, row) {
    const userId = Number(row.userId || row.kick_user_id);
    button.setAttribute?.('data-quiet-user', String(userId));
    button.disabled = quietPendingActions.has(String(userId));
    button.onclick = () => quietAction(action, row);
}
async function quietAction(action, row) {
    const userId = Number(row.userId || row.kick_user_id);
    const key = String(userId);
    if (!Number.isSafeInteger(userId) || userId <= 0 || quietPendingActions.has(key)) return;
    const question = action === 'ban'
        ? 'Permanently ban this KICK account? Previously verified network history will be checked after the ban. A network match alone is not proof of identity. Account bans and network blocks have separate undo controls.'
        : 'Ask this account to verify before chatting? Its chat access is temporarily restricted. An active request is reused, not replaced. A clean result restores only the verification restriction; flagged results need review.';
    if (!confirm(question)) return;
    quietPendingActions.add(key);
    quietButtons(userId, true);
    quietNotice(action === 'ban' ? 'Applying account ban…' : 'Preparing verification…');
    let confirmed = false;
    try {
        const response = await api(action === 'ban' ? '/api/moderate/ban' : '/api/verification/request', action === 'ban'
            ? { userId, shield: true, reason: 'StreamShield moderator-confirmed Ban & Shield' }
            : { userId, username: row.username || row.kick_username || '', messageId: row.messageId || '' });
        const raw = await response.text();
        let data = {}; try { data = raw ? JSON.parse(raw) : {}; } catch {}
        if (!response.ok) throw new Error(data.error || raw || 'The action could not be confirmed. Check the current moderation state before retrying.');
        confirmed = true;
        if (action === 'ban') {
            quietNotice(data.ban_shield?.message || 'Account ban confirmed. Check Network & Ban History for network status.');
        } else if (data.chat_message_sent) {
            quietNotice(data.chat_message_reused ? 'The existing verification link is already in chat. No new restriction or duplicate message was added.' : data.reused ? 'The active verification link was sent again. Its original expiry and restriction were preserved.' : 'Verification link sent in chat. A clean result restores the verification restriction automatically.');
        } else if (data.ready_message) {
            try {
                await navigator.clipboard.writeText(data.ready_message);
                quietNotice('Verification is active. KICK could not send the link, so the fallback message was copied.');
            } catch {
                quietNotice('Verification is active. KICK could not send the link; use the copy dialog.');
                prompt('Copy this verification message to the viewer:', data.ready_message);
            }
        } else {
            quietNotice('The request was accepted. Refresh verification history to check its status.');
        }
        // A refresh failure must never make a successful ban look unsuccessful.
        try {
            if (typeof loadVerificationQueue === 'function') await loadVerificationQueue();
            else if (typeof loadQueue === 'function') await loadQueue();
        } catch {}
    } catch (error) {
        quietNotice((confirmed ? 'Action accepted, but the display could not refresh. ' : '') + String(error?.message || 'Unable to confirm the action. Check the current moderation state before retrying.'), true);
    } finally {
        quietPendingActions.delete(key);
        quietButtons(userId, false);
    }
}
async function enableReviewFirstShield() {
    if (quietPendingActions.has('settings')) return;
    const n = current.networkProtection || {};
    if (n.enabled && !n.auto_ban_exact_network_match) { quietNotice('Network Shield is already in review-first mode.'); return; }
    if (!confirm(n.auto_ban_exact_network_match
        ? 'Switch Network Shield to review-first mode? Automatic permanent bans based only on exact network matches will be turned off. Existing KICK account bans and network blocks stay in place.'
        : 'Enable Network Shield in review-first mode? Viewers still choose whether to verify. Exact network matches will not automatically permanently ban accounts.')) return;
    quietPendingActions.add('settings');
    try {
        const r = await api('/api/network-protection', { enabled: true, autoBanExactNetworkMatch: false });
        if (!r.ok) throw new Error(await r.text());
        quietNotice('Network Shield enabled: review first. Existing account bans were not changed.');
    } catch (e) { quietNotice(String(e?.message || 'Could not update Network Shield.'), true); }
    finally { quietPendingActions.delete('settings'); }
}
`;
