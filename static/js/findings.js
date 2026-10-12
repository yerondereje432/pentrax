(() => {
  const body = document.getElementById('findings-body');
  if (!body) return;

  const rows = [...body.querySelectorAll('.finding-row')].map(row => ({ row, detail: row.nextElementSibling }));
  const riskRank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  let page = 1;
  const perPage = 40;
  let sortKey = '';
  let sortAsc = true;
  const controls = {
    risk: document.getElementById('risk-filter'),
    status: document.getElementById('status-filter'),
    service: document.getElementById('service-filter'),
    cve: document.getElementById('cve-filter'),
    text: document.getElementById('text-filter'),
  };

  const matching = () => rows.filter(item => {
    const data = item.row.dataset;
    return (!controls.risk.value || data.risk === controls.risk.value)
      && (!controls.status.value || data.status === controls.status.value)
      && (!controls.service.value || data.service.toLowerCase().includes(controls.service.value.toLowerCase()))
      && (!controls.cve.value || data.cve === controls.cve.value)
      && (!controls.text.value || data.search.includes(controls.text.value.toLowerCase()));
  });

  const sortRows = list => {
    if (!sortKey) return list;
    return [...list].sort((a, b) => {
      const av = sortKey === 'risk' ? (riskRank[a.row.dataset.risk] || 0) : Number(a.row.dataset[sortKey] || 0);
      const bv = sortKey === 'risk' ? (riskRank[b.row.dataset.risk] || 0) : Number(b.row.dataset[sortKey] || 0);
      return (av > bv ? 1 : av < bv ? -1 : 0) * (sortAsc ? 1 : -1);
    });
  };

  function render() {
    const filtered = sortRows(matching());
    const pages = Math.max(1, Math.ceil(filtered.length / perPage));
    page = Math.min(page, pages);
    const visible = filtered.slice((page - 1) * perPage, page * perPage);
    body.innerHTML = '';
    visible.forEach(item => body.append(item.row, item.detail));
    document.getElementById('results-count').textContent = filtered.length
      ? `Showing ${(page - 1) * perPage + 1}-${Math.min(page * perPage, filtered.length)} of ${filtered.length} results`
      : 'Showing 0 results';
    const pagination = document.getElementById('pagination');
    pagination.innerHTML = '';
    for (let index = 1; index <= pages; index += 1) {
      const button = document.createElement('button');
      button.textContent = index;
      button.className = index === page ? 'active' : '';
      button.addEventListener('click', () => { page = index; render(); });
      pagination.append(button);
    }
  }

  function statusClass(status) {
    return `status-${status.toLowerCase().replaceAll(' ', '-')}`;
  }

  async function saveStatus(select) {
    const row = select.closest('.finding-row');
    const previous = row.dataset.status;
    const status = select.value;
    select.disabled = true;
    try {
      const response = await fetch('/api/findings/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: select.dataset.findingKey, status }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not update status');
      row.dataset.status = data.status;
      select.className = `status-select ${statusClass(data.status)}`;
      if (window.yerscanToast) window.yerscanToast(`Status updated to ${data.status}`);
      if (controls.status.value && controls.status.value !== data.status) render();
    } catch (error) {
      select.value = previous;
      if (window.yerscanToast) window.yerscanToast(error.message);
    } finally {
      select.disabled = false;
    }
  }

  Object.values(controls).forEach(control => control.addEventListener(control.tagName === 'SELECT' ? 'change' : 'input', () => { page = 1; render(); }));
  document.querySelectorAll('[data-sort]').forEach(header => header.addEventListener('click', () => {
    const key = header.dataset.sort;
    sortAsc = sortKey === key ? !sortAsc : false;
    sortKey = key;
    render();
  }));
  body.addEventListener('change', event => {
    const select = event.target.closest('.status-select');
    if (select) saveStatus(select);
  });
  body.addEventListener('click', event => {
    if (event.target.closest('.status-cell')) return;
    const row = event.target.closest('.finding-row');
    if (!row) return;
    const detail = row.nextElementSibling;
    detail.classList.toggle('open');
    const indicator = row.querySelector('.expand-cell');
    if (indicator) indicator.textContent = detail.classList.contains('open') ? '-' : '+';
  });
  document.getElementById('export-csv').addEventListener('click', () => {
    const filtered = sortRows(matching());
    const headings = ['Host IP', 'Port', 'Service', 'Version', 'Risk Level', 'CVE ID', 'CVSS Score', 'Description', 'Remediation Status'];
    const csv = [headings, ...filtered.map(item => {
      const d = item.row.dataset;
      const cells = item.row.querySelectorAll('td');
      return [d.host, d.port, d.service, cells[3].textContent.trim(), d.risk, cells[5].textContent.trim() === '-' ? '' : cells[5].textContent.trim(), cells[6].textContent.trim() === '-' ? '' : cells[6].textContent.trim(), cells[7].textContent.trim(), d.status];
    })].map(row => row.map(value => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n');
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    link.download = 'yerscan-filtered-findings.csv';
    link.click();
    URL.revokeObjectURL(link.href);
  });

  render();
})();
