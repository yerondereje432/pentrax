(() => {
  const toast = message => { const el = document.getElementById('toast'); if (!el) return; el.textContent = message; el.classList.add('show'); clearTimeout(window.__toast); window.__toast = setTimeout(() => el.classList.remove('show'), 2500); };
  document.querySelectorAll('input[type="file"]').forEach(upload => upload.addEventListener('change', async event => {
    const file = event.target.files[0]; if (!file) return;
    const form = new FormData(); form.append('report', file);
    try { const response = await fetch('/api/reports/upload', { method: 'POST', body: form }); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Upload failed'); location.href = data.redirect; } catch (error) { toast(error.message); }
  }));
  window.yerscanToast = toast;
})();
