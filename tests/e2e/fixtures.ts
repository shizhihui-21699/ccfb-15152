import { test as base, expect, chromium, type BrowserContext } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import type { ServerMode } from '../../src/server/server.js';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const tsxBin = resolve(workspaceRoot, 'node_modules/.bin/tsx');
const serverEntry = resolve(workspaceRoot, 'src/server/main.ts');

interface ModeServer {
  port: number;
  baseUrl: string;
  restart(mode: ServerMode): Promise<void>;
  stop(): Promise<void>;
  incidentsJson(): Promise<unknown>;
}

/**
 * 每个 worker 一套独立：端口、数据目录、浏览器用户目录。
 * 关键：restart() 保持端口不变 —— 对浏览器来说是同源服务器「恢复干净」，
 * 正好复现真实事故中「源站修复后，受害者浏览器仍驻留恶意 SW」的场景。
 */
async function startModeServer(port: number, mode: ServerMode, dataDir: string): Promise<ChildProcess> {
  await mkdir(dataDir, { recursive: true });
  const child = spawn(tsxBin, [serverEntry], {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      SWGUARD_MODE: mode,
      SWGUARD_PORT: String(port),
      // 每个模式独立数据目录，避免事件相互污染
      SWGUARD_DATA_DIR: dataDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (b) => process.stdout.write(`[srv:${mode}] ${b}`));
  child.stderr?.on('data', (b) => process.stderr.write(`[srv:${mode}] ${b}`));

  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/__swguard/health`);
      if (res.ok) return child;
    } catch {
      /* 还没起来 */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  child.kill('SIGKILL');
  throw new Error(`测试服务器(${mode}) 启动超时`);
}

export const test = base.extend<{
  modeServer: ModeServer;
  persistentContext: BrowserContext;
}>({
  modeServer: async ({}, use) => {
    const port = 41000 + Math.floor(Math.random() * 8000);
    const dataRoot = await mkdtemp(resolve(tmpdir(), 'swguard-data-'));
    let mode: ServerMode = 'infected'; // 默认从感染态启动，用例按需 restart
    let child = await startModeServer(port, mode, resolve(dataRoot, mode));

    const server: ModeServer = {
      port,
      baseUrl: `http://127.0.0.1:${port}`,
      async restart(nextMode: ServerMode) {
        child.kill('SIGTERM');
        await new Promise((r) => child.once('exit', r));
        mode = nextMode;
        child = await startModeServer(port, mode, resolve(dataRoot, mode));
      },
      async stop() {
        child.kill('SIGTERM');
        await new Promise((r) => child.once('exit', r));
        await rm(dataRoot, { recursive: true, force: true });
      },
      async incidentsJson() {
        const res = await fetch(`http://127.0.0.1:${port}/__swguard/incidents`);
        return res.json();
      },
    };
    await use(server);
    await server.stop();
  },

  persistentContext: async ({}, use) => {
    // SW 需要持久化用户目录；每个测试文件独立 profile，保证注册状态隔离
    // launchPersistentContext 是 chromium 命名空间上的静态方法
    const userDataDir = await mkdtemp(resolve(tmpdir(), 'swguard-profile-'));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      serviceWorkers: 'allow',
    });
    await use(context);
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  },
});

export { expect };
