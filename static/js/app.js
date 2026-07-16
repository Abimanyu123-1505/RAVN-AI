/** RAVN AI — Client-side utilities */

document.querySelectorAll('.scan-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const id = btn.dataset.id;
    if (!id) return;

    const progress = document.getElementById('scanProgress');
    const stage = document.getElementById('scanStage');
    const percent = document.getElementById('scanPercent');
    const bar = document.getElementById('scanBar');

    if (progress) progress.classList.remove('hidden');
    btn.disabled = true;

    const stages = [
      [10, 'Initializing connection...'],
      [30, 'Checking SSL certificate...'],
      [55, 'Analyzing HTTP security headers...'],
      [75, 'Running DNS security checks...'],
    ];

    for (const [pct, msg] of stages) {
      if (stage) stage.textContent = msg;
      if (percent) percent.textContent = pct + '%';
      if (bar) bar.style.width = pct + '%';
      await new Promise((r) => setTimeout(r, 400));
    }

    try {
      const res = await fetch(`/websites/${id}/scan`, { method: 'POST' });
      const data = await res.json();

      if (stage) stage.textContent = 'Scan complete — ' + data.vulnerabilities.length + ' findings';
      if (percent) percent.textContent = '100%';
      if (bar) bar.style.width = '100%';

      setTimeout(() => window.location.reload(), 1200);
    } catch {
      if (stage) stage.textContent = 'Scan failed. Please try again.';
      btn.disabled = false;
    }
  });
});
