"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const bindBusyState = (formId, buttonId, loadingId, label) => {
        const form = document.getElementById(formId);
        if (!form) {
            return;
        }
        form.addEventListener("submit", (event) => {
            if (!form.checkValidity() || form.dataset.submitting === "true") {
                if (form.dataset.submitting === "true") {
                    event.preventDefault();
                }
                return;
            }
            form.dataset.submitting = "true";
            const button = document.getElementById(buttonId);
            const loading = document.getElementById(loadingId);
            if (button) {
                button.disabled = true;
                button.textContent = label;
            }
            if (loading) {
                loading.hidden = false;
            }
            form.setAttribute("aria-busy", "true");
        });
    };

    bindBusyState("assessment-form", "scan-button", "scan-loading", "Assessment running...");
    bindBusyState("dpi-capture-form", "dpi-capture-button", "dpi-capture-loading", "Capture running...");
    bindBusyState("website-block-form", "website-block-button", "website-block-loading", "Updating blocklist...");

    document.querySelectorAll("[data-domain-filter]").forEach((input) => {
        const list = document.getElementById(input.dataset.domainFilter);
        if (!list) {
            return;
        }
        input.addEventListener("input", () => {
            const query = input.value.trim().toLowerCase();
            list.querySelectorAll("[data-domain-row]").forEach((row) => {
                const domain = (row.dataset.domainValue || "").toLowerCase();
                row.hidden = Boolean(query) && !domain.includes(query);
            });
        });
    });

    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget);
            if (!target || !navigator.clipboard) {
                return;
            }
            try {
                await navigator.clipboard.writeText(target.textContent.trim());
                const originalLabel = button.textContent;
                button.textContent = "Copied";
                window.setTimeout(() => {
                    button.textContent = originalLabel;
                }, 1500);
            } catch (_error) {
                button.textContent = "Copy unavailable";
            }
        });
    });
});
