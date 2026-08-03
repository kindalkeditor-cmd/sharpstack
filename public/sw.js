self.addEventListener('push', e => {
  const data = e.data ? e.data.json() : { title: 'Sharp-Stack', body: 'Time to stack some knowledge 📚' };
  e.waitUntil(self.registration.showNotification(data.title || 'Sharp-Stack', {
    body: data.body || 'Your daily book insight is waiting',
    icon: '/icon.png',
    badge: '/icon.png',
    data: { url: 'https://www.sharp-stack.com' }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data?.url || 'https://www.sharp-stack.com'));
});
