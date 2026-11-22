import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { resolve, extname, normalize } from 'node:path';
import type { AddressInfo } from 'node:net';
import { loadManifest, findEntry, isAllowedScriptUrl, assertSafeRelativePath } from '../core/manifest.js';
import type { SiteManifest, RegistrationReport, ScriptRequestEvent } from '../core/types.js';
import { sha256Buffer } from '../core/hash.js';
import { IncidentStore } from './incidents.js';
import { renderKillSw } from './kill-sw.js';
import {
  scriptResponseHeaders,
  pageResponseHeaders,
  staticAssetHeaders,
  clearSiteDataHeaders,
  NO_STORE,
} from './headers.js';

export type ServerMode = 'clean' | 'infected' | 'remediating';

export interface SwGuardServerOptions {
  root: string;
  manifestPath: string;
  mode: ServerMode;
  port: number;
  dataDir: string;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

export class SwGuardServer {
  private manifest!: SiteManifest;
  private incidents!: IncidentStore;
  private readonly scriptRequests: ScriptRequestEvent[] = [];
  private readonly beaconReports: RegistrationReport[] = [];

  constructor(private readonly opts: SwGuardServerOptions) {}

  async start(): Promise<AddressInfo> {
    this.manifest = await loadManifest(this.opts.manifestPath, this.opts.root);
    this.incidents = new IncidentStore(resolve(this.opts.dataDir, 'incidents.jsonl'));

    const server = createServer((req, res) => {
      this.handle(req, res).catch((err) => {
        console.error('[server] 未捕获错误:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'internal' }));
        }
      });
    });

    return new Promise((resolveStart) => {
      server.listen(this.opts.port, '127.0.0.1', () => {
        resolveStart(server.address() as AddressInfo);
      });
    });
  }

  get mode(): ServerMode {
    return this.opts.mode;
  }

  getManifest(): SiteManifest {
    return this.manifest;
  }

  getIncidents(): IncidentStore {
    return this.incidents;
  }

  getScriptRequests(): ScriptRequestEvent[] {
    return this.scriptRequests;
  }

  getBeaconReports(): RegistrationReport[] {
    return this.beaconReports;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname;

    // ---- 管理端点 ----
    if (path === this.manifest.beacon.manifestEndpoint && req.method === 'GET') {
      this.writeJson(res, 200, this.publicManifest(), { 'cache-control': NO_STORE });
      return;
    }
    if (path === this.manifest.beacon.endpoint && req.method === 'POST') {
      await this.collectBeacon(req, res);
      return;
    }
    if (path === '/__swguard/incidents' && req.method === 'GET') {
      this.writeJson(res, 200, {
        mode: this.opts.mode,
        scriptRequests: this.scriptRequests,
        beaconReports: this.beaconReports,
        incidents: await this.incidents.all(),
      }, { 'cache-control': NO_STORE });
      return;
    }
    // 显式清除端点：响应 Clear-Site-Data（支持的浏览器会清空站点数据），
    // 但默认不携带 "cache"，避免误删合法离线缓存。
    if (path === '/__swguard/purge' && req.method === 'POST') {
      const includeCache = url.searchParams.get('cache') === '1';
      res.writeHead(200, {
        'content-type': 'application/json',
        ...clearSiteDataHeaders(includeCache),
      });
      res.end(JSON.stringify({ ok: true, includeCache, note: '精细缓存清理由 kill SW 完成' }));
      return;
    }
    // 健康检查：clean/remediating 模式由源站真实回答；infected 模式下恶意 SW 会伪造它
    if (path === '/__swguard/health' && req.method === 'GET') {
      this.writeJson(res, 200, {
        ok: true,
        version: this.manifest.serviceWorkers[0]?.version,
        source: 'origin',
      }, { 'cache-control': NO_STORE });
      return;
    }

    // ---- 演示页面 ----
    if (path === '/infected' && req.method === 'GET') {
      await this.servePage(res, 'infected.html');
      return;
    }

    // ---- SW 脚本请求（核心安全决策点）----
    const swHeader = req.headers['service-worker'];
    if (typeof swHeader === 'string') {
      await this.handleScriptRequest(req, res, path, swHeader);
      return;
    }

    // ---- 普通静态资源 ----
    await this.serveStatic(res, path);
  }

  /**
   * 处理浏览器内部发起的 SW 脚本请求/更新请求。
   * 关键点：该请求由浏览器网络栈发出，恶意 SW 的 fetch 事件收不到它，页面 JS 也无法伪造，
   * 因此这里的响应是整条清除链路里唯一不可被攻击者拦截的信道。
   */
  private async handleScriptRequest(
    req: IncomingMessage,
    res: ServerResponse,
    path: string,
    swHeader: string,
  ): Promise<void> {
    assertSafeRelativePath(path);
    const entry = findEntry(path, this.manifest);
    const allowed = isAllowedScriptUrl(path, this.manifest);
    const event: ScriptRequestEvent = {
      at: new Date().toISOString(),
      url: path,
      serviceWorkerHeader: swHeader,
      userAgent: req.headers['user-agent'] ?? '',
      known: Boolean(entry),
      matchedScript: entry?.scriptUrl,
    };
    this.scriptRequests.push(event);

    // 场景 A：清单内脚本 + clean → 下发真实合法字节（带硬化头）
    if (entry && this.opts.mode === 'clean') {
      await this.serveTrustedScript(res, entry.scriptUrl, entry.sha256);
      return;
    }

    // 场景 B：感染窗口期，清单内脚本也被投毒，下发恶意字节（模拟事故）
    if (entry && this.opts.mode === 'infected') {
      await this.incidents.record('hash-mismatch', {
        scriptUrl: entry.scriptUrl,
        note: '感染模式：源站正在下发被篡改的 SW 字节',
      });
      await this.serveFileAsScript(res, resolve(this.opts.root, 'sw/evil-sw.js'));
      return;
    }

    // 场景 C：应急清除阶段（kill-first）。
    // 即使是清单内的合法 URL 也先下发 kill SW：
    //  - 已感染访客：kill 夺权后精准删除恶意缓存并自注销
    //  - 干净访客：受保护前缀（app-v）不会被删，仅丢失注册，reconcile 会自动装回
    // 第二阶段把模式切回 clean，即完成「重新下发合法 SW」的二次部署。
    if (entry && this.opts.mode === 'remediating') {
      await this.incidents.record('remediation-kill', {
        scriptUrl: entry.scriptUrl,
        note: '应急清除窗口：对已知 URL 也下发 kill SW，清除潜伏的恶意版本与缓存',
      });
      const killSource = await renderKillSw(
        resolve(this.opts.root, 'sw/kill.js.template'),
        this.manifest,
        inferScope(entry.scriptUrl),
      );
      res.writeHead(200, {
        ...scriptResponseHeaders(this.manifest),
        'cache-control': NO_STORE,
        'x-swguard-action': 'kill-remediation-window',
      });
      res.end(killSource);
      return;
    }

    // 场景 C：清单外的 SW 脚本请求 —— 典型的「攻击者已注册隐藏 SW」信号。
    // 无论什么模式，一律下发 kill SW，并记录入侵事件。
    await this.incidents.record('unknown-script-request', {
      url: path,
      allowedPrefix: allowed,
      userAgent: event.userAgent,
    });
    const scope = inferScope(path);
    const killSource = await renderKillSw(resolve(this.opts.root, 'sw/kill.js.template'), this.manifest, scope);
    res.writeHead(200, {
      ...scriptResponseHeaders(this.manifest),
      'cache-control': NO_STORE,
      'x-swguard-action': 'kill-unknown-script',
    });
    res.end(killSource);
  }

  /** 下发清单内可信脚本，并在运行时复核 hash（防止磁盘文件在进程运行期被改） */
  private async serveTrustedScript(res: ServerResponse, scriptUrl: string, expectedHash: string): Promise<void> {
    const diskPath = resolve(this.opts.root, '.' + scriptUrl);
    const bytes = await readFile(diskPath);
    const actual = sha256Buffer(bytes);
    if (actual !== expectedHash.toLowerCase()) {
      // 运行期篡改：拒绝下发合法响应，改用 kill SW，避免把新投毒字节推给所有访客
      await this.incidents.record('hash-mismatch', { scriptUrl, expected: expectedHash, actual });
      const killSource = await renderKillSw(
        resolve(this.opts.root, 'sw/kill.js.template'),
        this.manifest,
        inferScope(scriptUrl),
      );
      res.writeHead(200, {
        ...scriptResponseHeaders(this.manifest),
        'cache-control': NO_STORE,
        'x-swguard-action': 'kill-hash-mismatch',
      });
      res.end(killSource);
      return;
    }
    res.writeHead(200, scriptResponseHeaders(this.manifest));
    res.end(bytes);
  }

  private async serveFileAsScript(res: ServerResponse, diskPath: string): Promise<void> {
    const bytes = await readFile(diskPath);
    res.writeHead(200, scriptResponseHeaders(this.manifest));
    res.end(bytes);
  }

  private async collectBeacon(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    try {
      const report = JSON.parse(body) as RegistrationReport;
      // 服务端复核：上报的 scriptURL 是否在清单内（上报内容一律不可信）
      const known =
        typeof report.scriptURL === 'string' &&
        this.manifest.serviceWorkers.some((e) => e.scriptUrl === safePath(report.scriptURL));
      this.beaconReports.push(report);
      if (!known && report.reason !== 'kill-signal') {
        await this.incidents.record('registration-report', {
          reason: report.reason,
          scriptURL: report.scriptURL,
          scope: report.scope,
          state: report.state,
          cacheNames: report.cacheNames ?? [],
        });
      }
      this.writeJson(res, 202, { accepted: true }, { 'cache-control': NO_STORE });
    } catch {
      this.writeJson(res, 400, { error: 'bad payload' });
    }
  }

  private async serveStatic(res: ServerResponse, pathInput: string): Promise<void> {
    const path = pathInput === '/' ? '/index.html' : pathInput;
    assertSafeRelativePath(path);
    const diskPath = resolve(this.opts.root, normalize('.' + path));
    if (!diskPath.startsWith(resolve(this.opts.root))) {
      this.writeJson(res, 403, { error: 'forbidden' });
      return;
    }
    try {
      const info = await stat(diskPath);
      if (!info.isFile()) throw new Error('not file');
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('not found');
      return;
    }
    const bytes = await readFile(diskPath);
    const mime = MIME[extname(diskPath)] ?? 'application/octet-stream';
    const isHtml = mime.includes('text/html');
    res.writeHead(200, {
      'content-type': mime,
      ...(isHtml ? pageResponseHeaders(this.manifest) : staticAssetHeaders(this.manifest)),
    });
    res.end(bytes);
  }

  private async servePage(res: ServerResponse, name: string): Promise<void> {
    const diskPath = resolve(this.opts.root, name);
    const bytes = await readFile(diskPath);
    res.writeHead(200, pageResponseHeaders(this.manifest));
    res.end(bytes);
  }

  /** 发给浏览器的清单：去掉服务端内部字段，只留调和所需内容 */
  private publicManifest() {
    return {
      serviceWorkers: this.manifest.serviceWorkers.map((e) => ({
        scriptUrl: e.scriptUrl,
        scope: e.scope,
        version: e.version,
        sha256: e.sha256,
        cachePrefixes: e.cachePrefixes,
      })),
      hardening: {
        updateViaCache: this.manifest.hardening.updateViaCache,
        pageCsp: this.manifest.hardening.pageCsp,
      },
      kill: { purgeStorageKeys: this.manifest.kill.purgeStorageKeys },
      beacon: this.manifest.beacon,
    };
  }

  private writeJson(res: ServerResponse, status: number, data: unknown, extra: Record<string, string> = {}): void {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': NO_STORE,
      ...extra,
    });
    res.end(JSON.stringify(data));
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c as Buffer));
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    req.on('error', rejectBody);
  });
}

/** SW scope 默认是脚本路径去掉最后一段 */
function inferScope(scriptPath: string): string {
  const idx = scriptPath.lastIndexOf('/');
  return idx <= 0 ? '/' : scriptPath.slice(0, idx + 1);
}

function safePath(url: string): string {
  try {
    return new URL(url, 'http://127.0.0.1').pathname;
  } catch {
    return url;
  }
}
