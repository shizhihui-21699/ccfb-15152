import { readFile } from 'node:fs/promises';
import type { SiteManifest } from '../core/types.js';

let cachedTemplate: string | null = null;

/**
 * 渲染 kill SW：把清单中的清除策略注入模板。
 * 每个被判定为恶意/未知的脚本 URL 都返回同一份 kill 字节（scope 取请求对应路径的天然 scope），
 * 保证无论攻击者注册了多少个 scope，更新通道都会收到可激活的清除脚本。
 */
export async function renderKillSw(
  templatePath: string,
  manifest: SiteManifest,
  scope: string,
): Promise<string> {
  cachedTemplate ??= await readFile(templatePath, 'utf8');
  const config = {
    scope,
    purgeCachePrefixes: manifest.kill.purgeCachePrefixes,
    purgeExactCacheNames: manifest.kill.purgeExactCacheNames,
    purgeStorageKeys: manifest.kill.purgeStorageKeys,
    // 受保护前缀 = 清单中所有合法 SW 的缓存前缀，kill 时绝不删除
    protectedPrefixes: [...new Set(manifest.serviceWorkers.flatMap((e) => e.cachePrefixes))],
  };
  if (!cachedTemplate.includes('/*__SWGUARD_KILL_CONFIG__*/')) {
    throw new Error('kill SW 模板占位符缺失');
  }
  return cachedTemplate.replace(
    '/*__SWGUARD_KILL_CONFIG__*/ {}',
    JSON.stringify(config),
  );
}
