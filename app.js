document.addEventListener('DOMContentLoaded', () => {
    const codeInput = document.getElementById('code-input');
    const scanBtn = document.getElementById('scan-btn');
    const btnText = scanBtn.querySelector('.btn-text');
    const spinner = document.getElementById('scan-spinner');
    const resultsContainer = document.getElementById('results-container');
    const summaryCard = document.getElementById('summary-card');
    const findingsList = document.getElementById('findings-list');
    const resetBtn = document.getElementById('reset-btn');

    scanBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) {
            alert('Please paste some code to scan.');
            return;
        }

        // Set loading state
        scanBtn.disabled = true;
        btnText.textContent = 'Scanning...';
        spinner.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        findingsList.innerHTML = '';
        summaryCard.innerHTML = '';
        resetBtn.style.display = 'none';

        try {
            const response = await fetch('https://vibecheck-sabiha.vercel.app/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code })
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server responded with status ${response.status}`);
            }

            const data = await response.json();
            renderResults(data.findings || []);

        } catch (error) {
            console.error('Scan error:', error);
            resultsContainer.classList.remove('hidden');
            summaryCard.innerHTML = `<div class="error-message">An error occurred during scanning: ${error.message}</div>`;
        } finally {
            // Reset loading state
            scanBtn.disabled = false;
            btnText.textContent = 'Scan Code';
            spinner.classList.add('hidden');
        }
    });

    // Reset button click handler — inside DOMContentLoaded so the element exists
    resetBtn.addEventListener('click', () => {
        codeInput.value = '';
        summaryCard.innerHTML = '';
        findingsList.innerHTML = '';
        resultsContainer.classList.add('hidden');
        resetBtn.style.display = 'none';
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    function renderResults(findings) {
        resultsContainer.classList.remove('hidden');
        resetBtn.style.display = 'block';
        resetBtn.style.margin = '1.5rem auto';

        if (findings.length === 0) {
            summaryCard.innerHTML = '🎉 No security issues found! Your vibe passes the check.';
            return;
        }

        // Calculate severity counts
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        findings.forEach(f => {
            const sev = f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1).toLowerCase() : 'Low';
            if (counts[sev] !== undefined) {
                counts[sev]++;
            } else {
                counts['Low']++;
            }
        });

        summaryCard.innerHTML = `
            ${findings.length} issue${findings.length === 1 ? '' : 's'} found:
            ${counts.Critical > 0 ? `<span class="severity-count" style="color: var(--critical)">${counts.Critical} Critical</span>` : ''}
            ${counts.High > 0 ? `<span class="severity-count" style="color: var(--high)">${counts.High} High</span>` : ''}
            ${counts.Medium > 0 ? `<span class="severity-count" style="color: var(--medium)">${counts.Medium} Medium</span>` : ''}
            ${counts.Low > 0 ? `<span class="severity-count" style="color: var(--low)">${counts.Low} Low</span>` : ''}
        `;

        findings.forEach(finding => {
            const severity = finding.severity ? finding.severity.toLowerCase() : 'low';

            const card = document.createElement('div');
            card.className = 'finding-card';

            card.innerHTML = `
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(finding.title)}</div>
                    <div class="badge ${severity}">${escapeHtml(finding.severity)}</div>
                </div>
                <div class="finding-explanation">
                    ${escapeHtml(finding.explanation)}
                </div>
                ${finding.suggested_fix ? `
                <div class="fix-container">
                    <div class="fix-header">SUGGESTED FIX</div>
                    <pre><code>${escapeHtml(finding.suggested_fix)}</code></pre>
                </div>
                ` : ''}
            `;

            findingsList.appendChild(card);
        });
    }

    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});