"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("assessment-form");
    if (!form) {
        return;
    }

    form.addEventListener("submit", () => {
        if (!form.checkValidity()) {
            return;
        }
        const button = document.getElementById("scan-button");
        const loading = document.getElementById("scan-loading");
        button.disabled = true;
        button.textContent = "Assessment running...";
        loading.hidden = false;
        form.setAttribute("aria-busy", "true");
    });
});
