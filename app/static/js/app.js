/**
 * RedSurface — Client-side utilities
 */

// Cancel a running scan
async function cancelScan(scanId) {
    if (!confirm('Cancel this running scan?')) return;
    try {
        await fetch('/api/scans/' + scanId + '/cancel', { method: 'POST' });
        location.reload();
    } catch (err) {
        alert('Failed to cancel scan: ' + err.message);
    }
}

// Delete a scan
async function deleteScan(scanId) {
    if (!confirm('Delete this scan and all its results?')) return;
    try {
        await fetch('/api/scans/' + scanId, { method: 'DELETE' });
        window.location.href = '/';
    } catch (err) {
        alert('Failed to delete scan: ' + err.message);
    }
}

// Poll scan status (used on results page)
function pollScanStatus(scanId, intervalMs = 5000) {
    const poll = async () => {
        try {
            const res = await fetch('/api/scans/' + scanId);
            const data = await res.json();
            if (data.status === 'completed' || data.status === 'failed') {
                location.reload();
            }
        } catch (e) { /* ignore */ }
    };
    setInterval(poll, intervalMs);
}
