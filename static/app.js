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
    // Live DPI handling
    const liveForm = document.getElementById('live-start-form');
    const startBtn = document.getElementById('live-start-button');
    const stopBtn = document.getElementById('live-stop-button');
    const statusDiv = document.getElementById('live-status');
    const statsPre = document.getElementById('live-stats');
    const eventsDiv = document.getElementById('live-events');
    const eventList = document.getElementById('event-list');
    let eventSource = null;

    function startLiveCapture(event) {
        event.preventDefault();
        const formData = new FormData(liveForm);
        fetch(liveForm.action, { method: 'POST', body: formData })
            .then(resp => {
                if (!resp.ok) throw new Error('Failed to start live capture');
                startBtn.hidden = true;
                stopBtn.hidden = false;
                statusDiv.hidden = false;
                eventsDiv.hidden = false;
                // Open Server‑Sent Events stream
                eventSource = new EventSource('/dpi/live/stream');
                eventSource.addEventListener('update', e => {
                    const data = JSON.parse(e.data);
                    if (statsPre) statsPre.textContent = JSON.stringify(data.stats, null, 2);
                    if (eventList) {
                        eventList.innerHTML = '';
                        data.events.forEach(ev => {
                            const li = document.createElement('li');
                            const ts = ev.timestamp ? ev.timestamp : '';
                            const proto = ev.transport_protocol || '';
                            const src = ev.src_ip || '';
                            const dst = ev.dst_ip || '';
                            li.textContent = `${ts} ${proto} ${src} → ${dst}`;
                            eventList.appendChild(li);
                        });
                    }
                });
                eventSource.onerror = () => {
                    console.error('SSE error, stopping live capture');
                    stopLiveCapture();
                };
            })
            .catch(err => {
                alert(err.message);
            });
    }

    function stopLiveCapture() {
        fetch('/dpi/live/stop', { method: 'POST' })
            .finally(() => {
                if (eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                if (startBtn) startBtn.hidden = false;
                if (stopBtn) stopBtn.hidden = true;
                if (statsPre) statsPre.textContent = '';
                if (eventList) eventList.innerHTML = '';
                if (statusDiv) statusDiv.hidden = true;
                if (eventsDiv) eventsDiv.hidden = true;
            });
    }

    if (liveForm) {
        liveForm.addEventListener('submit', startLiveCapture);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopLiveCapture);
    }

});
