// SPDX-License-Identifier: GPL-3.0-or-later
// Settings page: "Enable browser notifications" button. Plain JavaScript, no build step.
//
// iOS and iPadOS Safari only deliver Web Push to a web app added to the Home Screen -- a plain
// Safari tab cannot subscribe there (see docs/notifications.md, "Browser popups and push", for
// the primary sources). This script does not special-case that: PushManager.subscribe() simply rejects on a
// browser/context that does not support it, and the button shows that rejection as a plain
// message instead of pretending to succeed.

function urlBase64ToUint8Array(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function subscribeToPush(vapidPublicKey, csrfToken, statusEl) {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    statusEl.textContent = "This browser does not support push notifications.";
    return;
  }
  try {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      statusEl.textContent = "Notification permission was not granted.";
      return;
    }
    const registration = await navigator.serviceWorker.register("/static/push-sw.js");
    await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
    });
    const p256dh = bufferToBase64Url(subscription.getKey("p256dh"));
    const auth = bufferToBase64Url(subscription.getKey("auth"));
    const body = new URLSearchParams({
      csrf: csrfToken,
      endpoint: subscription.endpoint,
      p256dh: p256dh,
      auth: auth,
      label: navigator.userAgent.slice(0, 80),
    });
    const response = await fetch("/settings/notifications/push/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (response.ok) {
      window.location.reload();
    } else {
      statusEl.textContent = "Could not save the subscription on the server.";
    }
  } catch (err) {
    // A rejected subscribe() is the expected outcome on a browser/context that Web Push does
    // not reach yet -- for example a plain Safari tab on iOS/iPadOS that has not been added to
    // the Home Screen. Shown as a plain message, not a crash.
    statusEl.textContent = "Could not enable push notifications here: " + err.message;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const button = document.getElementById("push-subscribe-button");
  if (!button) return;
  button.addEventListener("click", () => {
    const statusEl = document.getElementById("push-subscribe-status");
    subscribeToPush(button.dataset.vapidKey, button.dataset.csrf, statusEl);
  });
});
