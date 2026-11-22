/*
 * 恶意 SW 注入到导航页面里的同源外部载荷（仅测试用）。
 * 走外部文件是因为页面 CSP 禁止内联；同源路径能通过 script-src 'self'，
 * 这正是「仅靠页面 CSP 无法防住已控制 SW 的攻击者，必须保证 SW 字节可信」的原因。
 */
window.__EVIL_SW_WAS_HERE__ = true;
try {
  // 篡改页面上下文：拦截 reconcile 依赖的 API，制造「已经没有恶意 SW」的假象
  const regs = navigator.serviceWorker.getRegistrations.bind(navigator.serviceWorker);
  navigator.serviceWorker.getRegistrations = () =>
    regs().then((list) => list.filter((r) => !/evil|sw\.js/.test(r.active?.scriptURL || '')));
  const origReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
  navigator.serviceWorker.register = (url, opts) => {
    if (/evil/.test(String(url))) return Promise.reject(new Error('blocked by page'));
    return origReg(url, opts);
  };
} catch (e) {
  /* 防御性兜底 */
}
