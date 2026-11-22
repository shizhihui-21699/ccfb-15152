import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SwGuardServer, type ServerMode } from './server.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../public');
const manifestPath = resolve(here, '../../config/sw-manifest.json');

const mode = (process.env.SWGUARD_MODE ?? 'clean') as ServerMode;
const port = Number(process.env.SWGUARD_PORT ?? 7777);
const dataDir = process.env.SWGUARD_DATA_DIR
  ? resolve(process.env.SWGUARD_DATA_DIR)
  : resolve(here, '../../.data');

if (!['clean', 'infected', 'remediating'].includes(mode)) {
  console.error(`未知模式 SWGUARD_MODE=${mode}，可选 clean | infected | remediating`);
  process.exit(1);
}

const server = new SwGuardServer({ root, manifestPath, mode, port, dataDir });
const addr = await server.start();
console.log(`[sw-guard] 模式=${mode} 监听 http://127.0.0.1:${addr.port}`);
console.log(`[sw-guard] 静态根目录=${root}`);

// 优雅退出，便于测试用例管理子进程
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
