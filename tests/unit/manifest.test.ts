import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { loadManifest, isAllowedScriptUrl, ManifestError } from '../../src/core/manifest.js';
import { sha256Buffer } from '../../src/core/hash.js';

const root = resolve(import.meta.dirname, '../../public');
const manifestPath = resolve(import.meta.dirname, '../../config/sw-manifest.json');

describe('清单加载与信任根', () => {
  it('FILLED_AT_RUNTIME 占位符被真实 hash 回填', async () => {
    const manifest = await loadManifest(manifestPath, root);
    expect(manifest.serviceWorkers[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('磁盘文件被篡改时拒绝启动（hash 不符）', async () => {
    const manifest = await loadManifest(manifestPath, root);
    const entry = manifest.serviceWorkers[0]!;
    const tampered = {
      ...manifest,
      serviceWorkers: [{ ...entry, sha256: 'a'.repeat(64) }],
    };
    const tmp = resolve(import.meta.dirname, '../.data/tampered-manifest.json');
    const { writeFile, mkdir } = await import('node:fs/promises');
    await mkdir(resolve(import.meta.dirname, '../.data'), { recursive: true });
    await writeFile(tmp, JSON.stringify(tampered));
    await expect(loadManifest(tmp, root)).rejects.toBeInstanceOf(ManifestError);
  });

  it('白名单前缀判断只依据清单，不接受请求参数', () => {
    return loadManifest(manifestPath, root).then((manifest) => {
      expect(isAllowedScriptUrl('/sw.js', manifest)).toBe(true);
      expect(isAllowedScriptUrl('/sw/evil-sw.js', manifest)).toBe(true); // 前缀允许，但具体信任还要看清单条目
      expect(isAllowedScriptUrl('/uploads/backdoor.js', manifest)).toBe(false);
      expect(isAllowedScriptUrl('//evil.example/x.js', manifest)).toBe(false);
    });
  });

  it('sha256 对相同字节稳定，对不同字节发散', () => {
    expect(sha256Buffer('abc')).toBe(sha256Buffer('abc'));
    expect(sha256Buffer('abc')).not.toBe(sha256Buffer('abd'));
  });
});
