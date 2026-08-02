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
});
