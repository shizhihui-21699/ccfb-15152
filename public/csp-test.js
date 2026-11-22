// CSP 防护测试页脚本
const out = document.getElementById('out');
const results = [];
async function attempt() {
  // 1) 跨源 worker：blob: 构造的 worker 不属于 'self'
  try {
    const blob = new Blob(["self.addEventListener('install', () => {})"], { type: 'text/javascript' });
    const blobUrl = URL.createObjectURL(blob);
    await navigator.serviceWorker.register(blobUrl);
    results.push('blob-worker: ALLOWED（不应出现）');
  } catch (e) {
    results.push(`blob-worker: blocked (${e.name})`);
  }

  // 2) data: URL worker
  try {
    await navigator.serviceWorker.register('data:text/javascript,self.addEventListener("install",()=>{})');
    results.push('data-worker: ALLOWED（不应出现）');
  } catch (e) {
    results.push(`data-worker: blocked (${e.name})`);
  }
  out.textContent = results.join('\n');
  window.__CSP_RESULT__ = results;
}
attempt();
