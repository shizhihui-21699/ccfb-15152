// 首页状态面板脚本
const logEl = document.getElementById('status-log');
const log = (msg) => {
  const li = document.createElement('li');
  li.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  logEl.prepend(li);
};

async function refresh() {
  const regs = await navigator.serviceWorker.getRegistrations().catch(() => []);
  const ctrl = navigator.serviceWorker.controller;
  const ctrlEl = document.getElementById('controller');
  if (ctrl) {
    const evil = /evil/.test(ctrl.scriptURL);
    ctrlEl.textContent = ctrl.scriptURL;
    ctrlEl.className = `badge ${evil ? 'bad' : 'ok'}`;
  } else {
    ctrlEl.textContent = '无控制器';
    ctrlEl.className = 'badge bad';
  }

  const markerEl = document.getElementById('evil-marker');
  if (window.__EVIL_SW_WAS_HERE__) {
    markerEl.textContent = '页面被恶意 SW 注入过脚本！';
    markerEl.className = 'badge bad';
  } else {
    markerEl.textContent = '未检测到注入';
    markerEl.className = 'badge ok';
  }

  const names = await caches.keys().catch(() => []);
  const cacheEl = document.getElementById('cache-state');
  const hasGood = names.some((n) => n.startsWith('app-v'));
  const hasEvil = names.some((n) => n.startsWith('evil-'));
  cacheEl.textContent = `${names.join(', ') || '（空）'}${hasEvil ? '（含恶意缓存）' : ''}`;
  cacheEl.className = `badge ${hasEvil ? 'bad' : hasGood ? 'ok' : 'bad'}`;
  log(`状态刷新：regs=${regs.length} caches=[${names.join(',')}]`);
}

document.getElementById('btn-update').addEventListener('click', async () => {
  const regs = await navigator.serviceWorker.getRegistrations();
  await Promise.all(regs.map((r) => r.update()));
  log('已对所有注册调用 update()');
  setTimeout(refresh, 1500);
});
document.getElementById('btn-unregister').addEventListener('click', async () => {
  const regs = await navigator.serviceWorker.getRegistrations();
  await Promise.all(regs.map((r) => r.unregister()));
  log(`已请求注销 ${regs.length} 个注册`);
  setTimeout(refresh, 500);
});
document.getElementById('btn-offline').addEventListener('click', async () => {
  const hit = await caches.match('/offline.html');
  log(hit ? '离线页缓存仍在（正常离线功能保留）' : '离线页缓存缺失');
});
document.getElementById('btn-refresh').addEventListener('click', refresh);

navigator.serviceWorker.addEventListener('controllerchange', () => {
  log('controllerchange 事件触发');
  setTimeout(refresh, 800);
});
refresh();
