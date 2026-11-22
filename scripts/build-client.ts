/**
 * 把页面侧 TS 库打包成浏览器可用的 IIFE（public/reconcile.js）。
 * 使用 esbuild（tsx 的依赖，无需额外安装）。
 */
import { build } from 'esbuild';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

await build({
  entryPoints: [resolve(root, 'src/client/reconcile.ts')],
  outfile: resolve(root, 'public/reconcile.js'),
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome110', 'edge110', 'safari16'],
  sourcemap: true,
  legalComments: 'none',
});

console.log('[build] public/reconcile.js 已生成');
