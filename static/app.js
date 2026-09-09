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
    let isStopping = false;

    function closeEventSourceSafely() {
        if (eventSource) {
            try {
                eventSource.close();
            } catch (err) {
                console.warn('Error closing EventSource:', err);
            }
            eventSource = null;
        }
    }

    function startLiveCapture(event) {
        event.preventDefault();
        isStopping = false;
        const formData = new FormData(liveForm);
        fetch(liveForm.action, { method: 'POST', body: formData })
            .then(resp => {
                if (!resp.ok) {
                    return resp.json().then(data => {
                        throw new Error(data.message || data.error || 'Failed to start live capture');
                    }).catch(err => {
                        if (err.message) throw err;
                        throw new Error('Failed to start live capture');
                    });
                }
                return resp.json();
            })
            .then(() => {
                startBtn.hidden = true;
                stopBtn.hidden = false;
                stopBtn.disabled = false;
                stopBtn.textContent = 'Stop capture';
                statusDiv.hidden = false;
                eventsDiv.hidden = false;

                // Close any existing SSE stream
                closeEventSourceSafely();

                // Open Server‑Sent Events stream
                eventSource = new EventSource('/dpi/live/stream');
                eventSource.addEventListener('update', e => {
                    if (isStopping) return;
                    try {
                        const data = JSON.parse(e.data);
                        if (statsPre) statsPre.textContent = JSON.stringify(data.stats, null, 2);
                        if (eventList && Array.isArray(data.events)) {
                            eventList.innerHTML = '';
                            data.events.forEach(ev => {
                                const li = document.createElement('li');
                                const ts = ev.timestamp ? ev.timestamp : '';
                                const proto = ev.transport_protocol || '';
                                const src = ev.source_ip || ev.src_ip || '';
                                const dst = ev.destination_ip || ev.dst_ip || '';
                                li.textContent = `${ts} ${proto} ${src} → ${dst}`;
                                eventList.appendChild(li);
                            });
                        }
                    } catch (parseErr) {
                        console.error('Error parsing SSE payload:', parseErr);
                    }
                });

                eventSource.onerror = () => {
                    // Stop SSE safely without causing recursion
                    closeEventSourceSafely();
                    if (!isStopping) {
                        console.warn('Live capture stream disconnected.');
                    }
                };
            })
            .catch(err => {
                alert(err.message || 'Failed to start live capture');
            });
    }

    function stopLiveCapture() {
        if (isStopping) {
            return;
        }
        isStopping = true;

        // Stop SSE safely
        closeEventSourceSafely();

        // Show "Finalizing capture..." on the button and do NOT clear dashboard immediately
        if (stopBtn) {
            stopBtn.disabled = true;
            stopBtn.textContent = 'Finalizing capture...';
        }

        fetch('/dpi/live/stop', {
            method: 'POST',
            headers: {
                'Accept': 'application/json'
            }
        })
            .then(resp => {
                if (!resp.ok) {
                    return resp.json().then(data => {
                        throw new Error(data.message || data.error || 'Failed to finalize live capture');
                    }).catch(err => {
                        if (err.message) throw err;
                        throw new Error('Failed to finalize live capture');
                    });
                }
                return resp.json();
            })
            .then(data => {
                if (data && data.result_url) {
                    window.location.href = data.result_url;
                } else if (data && data.capture_id) {
                    window.location.href = `/dpi/result/${data.capture_id}`;
                } else {
                    if (stopBtn) stopBtn.textContent = 'Capture stopped';
                }
            })
            .catch(err => {
                console.error('Finalize capture error:', err);
                alert(err.message || 'Failed to finalize capture session');
                isStopping = false;
                if (stopBtn) {
                    stopBtn.disabled = false;
                    stopBtn.textContent = 'Stop capture';
                }
            });
    }

    if (liveForm) {
        liveForm.addEventListener('submit', startLiveCapture);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopLiveCapture);
    }
});
