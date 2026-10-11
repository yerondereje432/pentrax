(() => {
  const summary = window.REPORT_SUMMARY || {};
  const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const colors = ['#f17a7e', '#efb75d', '#d8c563', '#71d9ac', '#73a7f7'];
  const common = { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#aab9c0', boxWidth: 10, font: { family: 'DM Mono', size: 10 } } } }, scales: { x: { ticks: { color: '#72828f', font: { family: 'DM Mono', size: 9 } }, grid: { color: 'rgba(162,186,204,.08)' } }, y: { beginAtZero: true, ticks: { color: '#72828f', precision: 0, font: { family: 'DM Mono', size: 9 } }, grid: { color: 'rgba(162,186,204,.08)' } } } };
  new Chart(document.getElementById('risk-chart'), { type: 'bar', data: { labels, datasets: [{ label: 'Hosts', data: labels.map(label => summary.risk_distribution?.[label] || 0), backgroundColor: colors, borderRadius: 3, barPercentage: .62 }] }, options: common });
  new Chart(document.getElementById('cve-chart'), { type: 'doughnut', data: { labels, datasets: [{ data: labels.map(label => summary.cve_distribution?.[label] || 0), backgroundColor: colors, borderWidth: 0, hoverOffset: 4 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '68%', plugins: { legend: { position: 'right', labels: { color: '#aab9c0', boxWidth: 10, font: { family: 'DM Mono', size: 9 }, padding: 12 } } } } });
})();
