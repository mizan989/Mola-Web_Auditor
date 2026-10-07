const form = document.getElementById("auditForm");
const urlInput = document.getElementById("url");
const button = document.getElementById("auditButton");
const panel = document.getElementById("scanPanel");
const statusText = document.getElementById("scanStatus");
const scanUrl = document.getElementById("scanUrl");
const progressBar = document.getElementById("progressBar");
const reportTitle = document.getElementById("reportTitle");
const copyButton = document.getElementById("copyButton");
const rescanButton = document.getElementById("rescanButton");

function normalizeUrl(value) {
  if (!/^https?:\/\//i.test(value)) {
    return `https://${value}`;
  }
  return value;
}

function runDemoScan() {
  const normalized = normalizeUrl(urlInput.value.trim());

  try {
    new URL(normalized);
  } catch {
    urlInput.focus();
    urlInput.setCustomValidity("Enter a valid website URL.");
    urlInput.reportValidity();
    return;
  }

  urlInput.setCustomValidity("");
  button.disabled = true;
  button.textContent = "Scanning…";
  panel.classList.remove("hidden");
  scanUrl.textContent = normalized;
  reportTitle.textContent = new URL(normalized).hostname;

  let progress = 0;
  const stages = [
    "Preparing scan",
    "Inspecting page",
    "Analyzing findings",
    "Building report"
  ];

  const timer = setInterval(() => {
    progress += 5;
    progressBar.style.width = `${progress}%`;

    const index = Math.min(Math.floor(progress / 25), stages.length - 1);
    statusText.textContent = stages[index];

    if (progress >= 100) {
      clearInterval(timer);
      statusText.textContent = "Demo scan complete";
      button.disabled = false;
      button.textContent = "Audit";
      document.getElementById("report").scrollIntoView({
        behavior: "smooth",
        block: "start"
      });
    }
  }, 100);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runDemoScan();
});

copyButton.addEventListener("click", async () => {
  const markdown = `# Mola Audit — ${reportTitle.textContent}

## Summary

- Findings: 12
- High priority: 4
- Evidence items: 7

## High

### Content-Security-Policy is missing

A CSP can reduce the impact of certain client-side injection attacks.

Evidence: response.headers["content-security-policy"] → missing

## Medium

### Meta description is missing

Add a concise description that accurately represents the page.

Evidence: <meta name="description"> → not found
`;

  try {
    await navigator.clipboard.writeText(markdown);
    copyButton.textContent = "Copied";
    setTimeout(() => copyButton.textContent = "Copy Markdown", 1400);
  } catch {
    copyButton.textContent = "Copy unavailable";
  }
});

rescanButton.addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
  setTimeout(() => urlInput.focus(), 500);
});
