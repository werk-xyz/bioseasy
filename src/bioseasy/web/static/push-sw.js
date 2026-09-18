// SPDX-License-Identifier: GPL-3.0-or-later
// Service worker for browser push notifications.
// Plain JavaScript only, no build step, per project convention. Registered from the Settings page
// (see static/push-subscribe.js) and only ever handles the "push" and "notificationclick" events
// -- it does not cache anything and is not a general-purpose offline service worker.

self.addEventListener("push", (event) => {
  let title = "bioseasy";
  let body = "";
  let url = "/";
  if (event.data) {
    try {
      const payload = event.data.json();
      title = payload.title || title;
      body = payload.body || body;
    } catch (err) {
      body = event.data.text();
    }
  }
  event.waitUntil(self.registration.showNotification(title, { body, data: { url } }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ("focus" in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});
