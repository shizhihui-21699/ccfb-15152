import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { renderKillSw } from '../../src/server/kill-sw.js';
import { loadManifest } from '../../src/core/manifest.js';
import type { SiteManifest } from '../../src/core/types.js';

const root = resolve(import.meta.dirname, '../../public');
const manifestPath = resolve(import.meta.dirname, '../../config/sw-manifest.json');
const templatePath = resolve(root, 'sw/kill.js.template');

describe('kill SW 渲染', () => {
  it('注入清除配置与受保护前缀，模板占位符被完全替换', async () => {
    const manifest = await loadManifest(manifestPath, root);
    const out = await renderKillSw(templatePath, manifest, '/');
    expect(out).not.toContain('__SWGUARD_KILL_CONFIG__');
    expect(out).toContain('"purgeCachePrefixes"');
    expect(out).toContain('evil-');
    // 合法缓存前缀必须被保护
    expect(out).toContain('"app-v"');
  });

  it('注入的 JSON 是合法表达式（Function 构造仅用于测试解析，不在产品代码中）', async () => {
    const manifest: SiteManifest = await loadManifest(manifestPath, root);
    const out = await renderKillSw(templatePath, manifest, '/sub/');
    expect(out).toContain('"scope":"/sub/"');
    // 提取配置对象验证可解析：定位 KILL_CONFIG 声明后的第一个花括号对（跨多行，忽略字符串内括号）
    const decl = out.indexOf('const KILL_CONFIG');
    expect(decl).toBeGreaterThan(-1);
    // 跳过同行的 JSDoc 注释，定位真正的配置对象起始花括号
    const afterComment = out.indexOf('*/', decl) + 2;
    const start = out.indexOf('{', afterComment);
    let depth = 0;
    let inString: false | '"' | "'" = false;
    let end = -1;
    for (let i = start; i < out.length; i++) {
      const ch = out[i]!;
      if (inString) {
        if (ch === inString && out[i - 1] !== '\\') inString = false;
        continue;
      }
      if (ch === '"' || ch === "'") inString = ch as '"' | "'";
      else if (ch === '{') depth++;
      else if (ch === '}' && --depth === 0) {
        end = i;
        break;
      }
    }
    expect(end).toBeGreaterThan(start);
    const parsed = JSON.parse(out.slice(start, end + 1)) as { protectedPrefixes: string[] };
    expect(parsed.protectedPrefixes).toContain('app-v');
  });
});
