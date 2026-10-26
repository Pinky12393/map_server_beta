const authView = document.querySelector('#auth-view');
const mapView = document.querySelector('#map-view');
const authError = document.querySelector('#auth-error');
const drawer = document.querySelector('#app-drawer');
const drawerBackdrop = document.querySelector('#drawer-backdrop');
const csrfCookieName = 'csrf_token';

let map;
let currentUser;
let watchId = null;
let myMarker = null;
let osmRequestController = null;
let mapLoadTimer = null;
let friendPollTimer = null;
let lastKnownPosition = null;

const layers = {
  gyms: L.layerGroup(),
  cycle: L.layerGroup(),
  friends: L.layerGroup(),
};

function cookie(name) {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith(`${name}=`))
    ?.split('=')[1] || '';
}

async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    headers.set('X-CSRF-Token', decodeURIComponent(cookie(csrfCookieName)));
  }

  const response = await fetch(path, { ...options, method, headers, credentials: 'same-origin' });
  let data = null;
  try { data = await response.json(); } catch (_) { data = {}; }
  if (!response.ok) throw new Error(data.detail || `Ошибка ${response.status}`);
  return data;
}

function showToast(text) {
  const toast = document.querySelector('#toast');
  toast.textContent = text;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 2800);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function initials(name) {
  const parts = String(name || 'Я').trim().split(/\s+/).filter(Boolean);
  return parts.slice(0, 2).map(part => part[0]).join('').toUpperCase() || 'Я';
}

function switchAuthMode(mode) {
  const login = mode === 'login';
  document.querySelector('#login-form').hidden = !login;
  document.querySelector('#register-form').hidden = login;
  document.querySelector('#show-login').classList.toggle('active', login);
  document.querySelector('#show-register').classList.toggle('active', !login);
  document.querySelector('#show-login').setAttribute('aria-selected', String(login));
  document.querySelector('#show-register').setAttribute('aria-selected', String(!login));
  authError.textContent = '';
}

document.querySelector('#show-login').addEventListener('click', () => switchAuthMode('login'));
document.querySelector('#show-register').addEventListener('click', () => switchAuthMode('register'));

document.querySelector('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  authError.textContent = '';
  const body = Object.fromEntries(new FormData(event.currentTarget));
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(body) });
    await enterApp(data.user);
  } catch (error) {
    authError.textContent = error.message;
  }
});

document.querySelector('#register-form').addEventListener('submit', async event => {
  event.preventDefault();
  authError.textContent = '';
  const body = Object.fromEntries(new FormData(event.currentTarget));
  try {
    const data = await api('/api/auth/register', { method: 'POST', body: JSON.stringify(body) });
    await enterApp(data.user);
  } catch (error) {
    authError.textContent = error.message;
  }
});

function initMap() {
  if (map) return;

  map = L.map('map', {
    zoomControl: false,
    minZoom: 2,
    maxZoom: 19,
    worldCopyJump: true,
    preferCanvas: true,
  }).setView([51.2, 18.3], 4);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    minZoom: 2,
    maxZoom: 19,
    attribution: '&copy; OpenStreetMap contributors',
  }).addTo(map);

  layers.gyms.addTo(map);
  layers.cycle.addTo(map);
  layers.friends.addTo(map);

  map.on('moveend', scheduleMapObjectsLoad);
  map.on('zoomend', updateActivityChip);
  scheduleMapObjectsLoad();
}

async function enterApp(user) {
  currentUser = user;
  authView.hidden = true;
  mapView.hidden = false;

  const short = initials(user.name);
  document.querySelector('#user-name').textContent = user.name;
  document.querySelector('#user-email').textContent = user.email;
  document.querySelector('#share-location').checked = user.share_location;
  document.querySelector('#profile-initial').textContent = short;
  document.querySelector('#nav-profile-initial').textContent = short;
  document.querySelector('#profile-avatar-large').textContent = short;

  initMap();
  requestAnimationFrame(() => map.invalidateSize(false));
  setTimeout(() => map.invalidateSize(false), 180);

  await refreshFriends();
  await refreshFriendLocations();
  clearInterval(friendPollTimer);
  friendPollTimer = setInterval(refreshFriendLocations, 5000);
  updateActivityChip();
}

function scheduleMapObjectsLoad() {
  clearTimeout(mapLoadTimer);
  mapLoadTimer = setTimeout(loadMapObjects, 420);
}

function updateActivityChip(friendCount = null) {
  const text = document.querySelector('#activity-text');
  if (friendCount !== null) {
    text.dataset.friendCount = String(friendCount);
  }
  const count = Number(text.dataset.friendCount || 0);
  if (!map || map.getZoom() < 11) {
    text.textContent = count ? `${count} друзей на карте · приблизь` : 'приблизь карту к своему городу';
  } else {
    text.textContent = count ? `${count} друзей рядом` : 'ищем активные места рядом';
  }
}

async function loadMapObjects() {
  if (!map || map.getZoom() < 11) {
    layers.gyms.clearLayers();
    layers.cycle.clearLayers();
    updateActivityChip();
    return;
  }

  const b = map.getBounds();
  const bbox = [b.getSouth(), b.getWest(), b.getNorth(), b.getEast()].join(',');
  if (osmRequestController) osmRequestController.abort();
  osmRequestController = new AbortController();

  try {
    const response = await fetch(`/api/map/objects?bbox=${encodeURIComponent(bbox)}`, {
      signal: osmRequestController.signal,
      credentials: 'same-origin',
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Ошибка загрузки карты');
    renderOsm(data.elements || []);
  } catch (error) {
    if (error.name !== 'AbortError') showToast(error.message);
  }
}

function objectIcon(type) {
  const isBike = type === 'bike';
  return L.divIcon({
    className: '',
    html: `<div class="object-marker ${isBike ? 'bike' : 'gym'}">${isBike ? 'В' : 'З'}</div>`,
    iconSize: [34, 34],
    iconAnchor: [17, 17],
    popupAnchor: [0, -20],
  });
}

function renderOsm(elements) {
  layers.gyms.clearLayers();
  layers.cycle.clearLayers();

  for (const item of elements) {
    const tags = item.tags || {};
    const name = escapeHtml(tags.name || 'Без названия');
    const isGym = ['fitness_centre', 'sports_centre'].includes(tags.leisure);
    const isBikePoint = ['bicycle_rental', 'bicycle_parking'].includes(tags.amenity);
    const isCycle = tags.highway === 'cycleway' || Object.hasOwn(tags, 'cycleway');

    if (item.type === 'node' && Number.isFinite(item.lat) && Number.isFinite(item.lon)) {
      if (isGym || isBikePoint) {
        const type = isBikePoint ? 'Велообъект' : 'Спортивный объект';
        L.marker([item.lat, item.lon], { icon: objectIcon(isBikePoint ? 'bike' : 'gym') })
          .bindPopup(`<strong>${name}</strong><br>${type}`)
          .addTo(layers.gyms);
      }
      continue;
    }

    if (item.type === 'way' && Array.isArray(item.geometry) && item.geometry.length > 1) {
      const coords = item.geometry.map(point => [point.lat, point.lon]);
      if (isCycle) {
        L.polyline(coords, { color: '#0b86d1', weight: 4, opacity: .86 })
          .bindPopup(`<strong>${name}</strong><br>Велодорожка`)
          .addTo(layers.cycle);
      } else if (isGym) {
        L.polygon(coords, { color: '#176242', weight: 2, fillColor: '#51c58a', fillOpacity: .22 })
          .bindPopup(`<strong>${name}</strong><br>Спортивный объект`)
          .addTo(layers.gyms);
      }
    }
  }
}

function setTrackingStatus(text) {
  document.querySelector('#tracking-status').textContent = text;
}

function startTracking() {
  if (!navigator.geolocation) {
    setTrackingStatus('Браузер не поддерживает геолокацию');
    return;
  }
  if (!document.querySelector('#share-location').checked) {
    showToast('Сначала включите показ геолокации друзьям');
    return;
  }
  if (watchId !== null) {
    if (lastKnownPosition) map.setView(lastKnownPosition, Math.max(map.getZoom(), 14));
    return;
  }

  setTrackingStatus('Запрашиваю доступ к геолокации…');
  watchId = navigator.geolocation.watchPosition(
    async position => {
      const { latitude: lat, longitude: lng, accuracy } = position.coords;
      lastKnownPosition = [lat, lng];
      setTrackingStatus(`Геолокация активна · точность около ${Math.round(accuracy)} м`);
      drawMyLocation(lat, lng, accuracy);
      try {
        await api('/api/location', {
          method: 'PUT',
          body: JSON.stringify({ lat, lng, accuracy }),
        });
      } catch (error) {
        setTrackingStatus(error.message);
      }
    },
    error => setTrackingStatus(`Геолокация недоступна: ${error.message}`),
    { enableHighAccuracy: true, maximumAge: 5000, timeout: 15000 },
  );
}

function stopTracking() {
  if (watchId !== null) navigator.geolocation.clearWatch(watchId);
  watchId = null;
  lastKnownPosition = null;
  if (myMarker && map) map.removeLayer(myMarker);
  myMarker = null;
  setTrackingStatus('Геолокация выключена');
}

function drawMyLocation(lat, lng, accuracy) {
  const icon = L.divIcon({
    className: '',
    html: '<div class="my-marker-wrap"><div class="my-marker"></div></div>',
    iconSize: [34, 34],
    iconAnchor: [17, 17],
  });
  if (!myMarker) {
    myMarker = L.marker([lat, lng], { icon, zIndexOffset: 700 }).addTo(map).bindPopup('Вы здесь');
    map.setView([lat, lng], Math.max(map.getZoom(), 14));
  } else {
    myMarker.setLatLng([lat, lng]);
  }
  myMarker.setPopupContent(`Вы здесь<br>Точность около ${Math.round(accuracy)} м`);
}

document.querySelector('#start-tracking').addEventListener('click', startTracking);
document.querySelector('#locate-button').addEventListener('click', startTracking);
document.querySelector('#world-button').addEventListener('click', () => map.setView([51.2, 18.3], 4));
document.querySelector('#activity-chip').addEventListener('click', () => {
  if (lastKnownPosition) map.setView(lastKnownPosition, 14);
  else showToast('Нажмите кнопку прицела и разрешите геолокацию');
});

document.querySelector('#share-location').addEventListener('change', async event => {
  const share_location = event.target.checked;
  try {
    const data = await api('/api/privacy', { method: 'PATCH', body: JSON.stringify({ share_location }) });
    currentUser = data.user;
    if (!share_location) stopTracking();
  } catch (error) {
    event.target.checked = !share_location;
    showToast(error.message);
  }
});

document.querySelector('#friend-form').addEventListener('submit', async event => {
  event.preventDefault();
  const message = document.querySelector('#friend-message');
  const body = Object.fromEntries(new FormData(event.currentTarget));
  try {
    await api('/api/friends/request', { method: 'POST', body: JSON.stringify(body) });
    message.textContent = 'Заявка отправлена';
    event.currentTarget.reset();
    await refreshFriends();
  } catch (error) {
    message.textContent = error.message;
  }
});

async function refreshFriends() {
  try {
    const data = await api('/api/friends');
    renderFriends(data.items || []);
  } catch (error) {
    showToast(error.message);
  }
}

function renderFriends(items) {
  const root = document.querySelector('#friends-list');
  if (!items.length) {
    root.innerHTML = '<p class="drawer-hint">Друзей и заявок пока нет.</p>';
    return;
  }

  root.replaceChildren(...items.map(item => {
    const card = document.createElement('div');
    card.className = 'friend-card';
    const friend = item.friend || { name: 'Пользователь', email: '' };
    const statusText = item.status === 'accepted'
      ? 'Друг'
      : item.direction === 'incoming' ? 'Входящая заявка' : 'Заявка отправлена';

    const friendShort = escapeHtml(initials(friend.name));
    card.innerHTML = `
      <div class="friend-copy">
        <div class="friend-list-avatar">${friendShort}</div>
        <p><strong>${escapeHtml(friend.name)}</strong><small>${escapeHtml(friend.email)}</small><small>${statusText}</small></p>
      </div>`;

    const actions = document.createElement('div');
    actions.className = 'friend-actions';
    if (item.status === 'pending' && item.direction === 'incoming') {
      const accept = document.createElement('button');
      accept.textContent = 'Принять';
      accept.addEventListener('click', async () => {
        try {
          await api(`/api/friends/${item.id}/accept`, { method: 'POST' });
          await refreshFriends();
          await refreshFriendLocations();
        } catch (error) {
          showToast(error.message);
        }
      });
      actions.append(accept);
    }

    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.textContent = item.status === 'accepted' ? 'Удалить' : 'Отменить';
    remove.addEventListener('click', async () => {
      try {
        await api(`/api/friends/${item.id}`, { method: 'DELETE' });
        await refreshFriends();
        await refreshFriendLocations();
      } catch (error) {
        showToast(error.message);
      }
    });
    actions.append(remove);
    card.append(actions);
    return card;
  }));
}

async function refreshFriendLocations() {
  try {
    const data = await api('/api/friends/locations');
    const items = data.items || [];
    layers.friends.clearLayers();
    updateActivityChip(items.length);

    for (const item of items) {
      const short = escapeHtml(initials(item.user.name));
      const minutes = Math.floor(item.location.age_seconds / 60);
      const ageLabel = minutes < 1 ? 'сейчас' : `${minutes}м`;
      const icon = L.divIcon({
        className: '',
        html: `<div class="friend-marker-wrap"><div class="friend-marker">${short}</div><div class="friend-time">${ageLabel}</div></div>`,
        iconSize: [58, 68],
        iconAnchor: [29, 58],
        popupAnchor: [0, -52],
      });

      L.marker([item.location.lat, item.location.lng], { icon, zIndexOffset: 600 })
        .bindPopup(`<strong>${escapeHtml(item.user.name)}</strong><br>Обновлено ${minutes < 1 ? 'только что' : `${minutes} мин. назад`}`)
        .addTo(layers.friends);
    }
  } catch (error) {
    if (!String(error.message).includes('Требуется вход')) console.warn(error);
  }
}

for (const [checkboxId, layerName] of [
  ['layer-gyms', 'gyms'],
  ['layer-cycle', 'cycle'],
  ['layer-friends', 'friends'],
]) {
  document.querySelector(`#${checkboxId}`).addEventListener('change', event => {
    if (!map) return;
    if (event.target.checked) layers[layerName].addTo(map);
    else map.removeLayer(layers[layerName]);
  });
}

const drawerMeta = {
  friends: { title: 'Друзья', kicker: 'Люди рядом', panel: '#panel-friends' },
  layers: { title: 'Слои карты', kicker: 'Что показывать', panel: '#panel-layers' },
  profile: { title: 'Твой профиль', kicker: 'Приватность и геолокация', panel: '#panel-profile' },
};

function closeDrawer() {
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  drawerBackdrop.hidden = true;
  document.querySelectorAll('.nav-item').forEach(button => {
    button.classList.toggle('active', button.dataset.panel === 'map');
  });
}

function openDrawer(type) {
  const meta = drawerMeta[type];
  if (!meta) {
    closeDrawer();
    return;
  }

  document.querySelectorAll('.drawer-panel').forEach(panel => { panel.hidden = true; });
  document.querySelector(meta.panel).hidden = false;
  document.querySelector('#drawer-title').textContent = meta.title;
  document.querySelector('#drawer-kicker').textContent = meta.kicker;
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  drawerBackdrop.hidden = false;
  document.querySelectorAll('.nav-item').forEach(button => {
    button.classList.toggle('active', button.dataset.panel === type);
  });
}

document.querySelectorAll('.nav-item').forEach(button => {
  button.addEventListener('click', () => {
    const type = button.dataset.panel;
    if (type === 'map') closeDrawer();
    else openDrawer(type);
  });
});

document.querySelector('#layers-button').addEventListener('click', () => openDrawer('layers'));
document.querySelector('#profile-chip').addEventListener('click', () => openDrawer('profile'));
document.querySelector('#drawer-close').addEventListener('click', closeDrawer);
drawerBackdrop.addEventListener('click', closeDrawer);

document.querySelector('#logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) {}
  stopTracking();
  clearInterval(friendPollTimer);
  location.reload();
});

(async function bootstrap() {
  try {
    const data = await api('/api/me');
    await enterApp(data.user);
  } catch (_) {
    authView.hidden = false;
    mapView.hidden = true;
    switchAuthMode('login');
  }
})();
