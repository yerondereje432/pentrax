(() => {
  const data = window.HISTORY_DATA || {};
  const selector = document.getElementById('history-target');
  const canvas = document.getElementById('history-chart');
  const label = document.getElementById('chart-target-label');
  if (!selector || !canvas || typeof Chart === 'undefined') return;

  let chart;
  const formatDate = value => value ? value.replace('T', ' · ').slice(0, 16) : 'No timestamp';
  const render = target => {
    const series = data[target] || [];
    if (label) label.textContent = target;
    if (chart) chart.destroy();
    chart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: series.map(item => formatDate(item.scan_time)),
        datasets: [
          { label: 'Open ports', data: series.map(item => item.open_ports || 0), borderColor: '#5de0df', backgroundColor: 'rgba(93,224,223,.12)', pointBackgroundColor: '#5de0df', pointRadius: 3, tension: .32, fill: true, yAxisID: 'y' },
          { label: 'CVEs', data: series.map(item => item.cves_found || 0), borderColor: '#efb75d', backgroundColor: 'rgba(239,183,93,.08)', pointBackgroundColor: '#efb75d', pointRadius: 3, tension: .32, fill: false, yAxisID: 'y' },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: { legend: { labels: { color: '#aab9c0', boxWidth: 10, font: { family: 'DM Mono', size: 10 } } } },
        scales: {
          x: { ticks: { color: '#72828f', font: { family: 'DM Mono', size: 9 }, maxRotation: 0, autoSkip: true }, grid: { color: 'rgba(162,186,204,.08)' } },
          y: { beginAtZero: true, ticks: { color: '#72828f', precision: 0, font: { family: 'DM Mono', size: 9 } }, grid: { color: 'rgba(162,186,204,.08)' } },
        },
      },
    });
  };

  selector.addEventListener('change', () => render(selector.value));
  render(selector.value || Object.keys(data)[0]);
})();
