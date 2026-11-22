import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readdir, readFile } from 'node:fs/promises';
import { loadManifest } from '../core/manifest.js';
import { scanServiceWorkerFile, checkImportScripts } from './static-scanner.js';
import { auditLiveSwScript, type FetchLike } from './live-audit.js';
import { renderReport } from './report.js';
import type { AuditFinding, AuditReport, Severity } from '../core/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const publicDir = resolve(root, 'public');
const manifestPath = resolve(root, 'config/sw-manifest.json');

interface CliArgs {
  command: 'scan' | 'live' | 'all';
  target?: string;
  json: boolean;
  /** 默认只扫清单登记的可信 SW；--all 额外扫描测试/教学用恶意样本 */
  all: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const positional = argv.filter((a) => !a.startsWith('--'));
  return {
    command: (positional[0] as CliArgs['command']) ?? 'all',
    target: positional[1],
    json: argv.includes('--json'),
    all: argv.includes('--all'),
  };
}

async function collectSwFiles(target: string | undefined, manifest: Awaited<ReturnType<typeof loadManifest>>, all: boolean): Promise<string[]> {
  if (target) return [resolve(process.cwd(), target)];
  if (!all) {
    // CI 默认视角：只扫描清单登记、会被真正下发的可信脚本
    return manifest.serviceWorkers.map((entry) => resolve(publicDir, '.' + entry.scriptUrl));
  }
  // 审计视角：扫描 public 下全部 JS（含测试用恶意样本），用于演示规则命中
  const out: string[] = [];
  await walk(publicDir, out);
  return out.filter((f) => f.endsWith('.js') && !f.endsWith('.template'));
}

async function walk(dir: string, out: string[]): Promise<void> {
  let entries: import('node:fs').Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) await walk(full, out);
    else out.push(full);
  }
}

const nodeFetch: FetchLike = (url, init) =>
  fetch(url, init).then(async (res) => ({
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    text: () => res.text(),
  }));

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const manifest = await loadManifest(manifestPath, publicDir);
  const findings: AuditFinding[] = [];

  if (args.command === 'scan' || args.command === 'all') {
    const files = await collectSwFiles(args.target, manifest, args.all);
    for (const file of files) {
      const { findings: fileFindings } = await scanServiceWorkerFile(file);
      findings.push(...fileFindings);

      // importScripts 白名单校验
      const source = await readFile(file, 'utf8');
      findings.push(...checkImportScripts(source, manifest.hardening.allowedImportPrefixes));
    }
  }

  if (args.command === 'live' || args.command === 'all') {
    const baseUrl = args.target ?? process.env.SWGUARD_BASE_URL ?? 'http://127.0.0.1:7777';
    findings.push(...(await auditLiveSwScript({ baseUrl, fetchImpl: nodeFetch }, manifest)));
  }

  const summary: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  const report: AuditReport = {
    generatedAt: new Date().toISOString(),
    target: args.target ?? 'default (public/ + http://127.0.0.1:7777)',
    summary,
    findings,
  };

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderReport(report));
  }

  // error 级命中 → 非零退出码，供 CI 门禁使用
  return summary.error > 0 ? 2 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[audit] 执行失败:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
