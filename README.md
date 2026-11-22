# SW Guard · Service Worker 安全管理方案（TypeScript）

针对「网站被注入恶意 Service Worker，源站修复后访客浏览器仍长期执行攻击者代码」这一问题的完整工程方案。包含**发现、清除、预防、上线前检测**四个子系统，并用本地测试站点 + Playwright 浏览器自动化验证完整攻击-恢复链（11 个 E2E + 10 个单元测试，全部通过）。

---

## 1. 问题本质：为什么源站干净了，访客还在中毒

Service Worker（SW）注册后独立于页面和源站生命周期持久存在：

- 它驻留在浏览器里，能拦截作用域（scope）内的**所有导航与请求**，即使之后源站 HTML/JS 全部换干净；
- 浏览器只在特定时机做「脚本更新检查」，且有缓存与节流规则；
- 恶意 SW 可以改写页面上下文的 `navigator.serviceWorker` API、伪造 postMessage 回执、伪造同源接口响应，让页面自己的清除代码失效。

所以「修掉注入漏洞」只解决了新增感染，**已感染访客需要一条他们拦不住的收敛信道**。

## 2. 浏览器 SW 更新与缓存规则（方案的事实基础）

| 规则 | 本方案的利用方式 |
| --- | --- |
| SW 脚本更新请求由**浏览器内部网络栈**发起，带请求头 `Service-Worker: script`；页面 JS 与已注册 SW 的 `fetch` 事件都收不到、拦不住、伪造不了这个响应 | 这是清除链路唯一不可阻断的信道，kill SW 经此下发 |
| 响应字节与现有 SW 不同 → 触发 install；`skipWaiting()` + `clients.claim()` 可让新版本立即夺权 | kill SW 用这套 API 把收敛时间压到最短 |
| `updateViaCache` 控制更新请求是否走 HTTP 缓存；`'none'` 时脚本与 importScripts 都绕缓存回源 | 注册强制 `updateViaCache:'none'` + 脚本 `Cache-Control: no-store/max-age=0`，杜绝缓存投毒 |
| 浏览器有更新节流（短时间内重复 `update()` 可能被忽略），导航时也会自动检查 | 清除不依赖单次 `update()`：页面 `update()` + CDP/调试信道 + 后续导航的自动检查多重触发 |
| SW 内 `caches`（CacheStorage）按名称隔离，与页面同源存储分开 | 用缓存名前缀区分合法/恶意数据，实现「精准清除、不误伤离线功能」 |
| `unregister()` 只注销注册，不自动删缓存；注销后若脚本 URL 仍可被注册，SW 会被装回 | kill SW 先清缓存再自注销；页面 reconcile 随后只装回清单内的合法 SW |

> 关键推论：**凡是只靠页面 JS 或 postMessage 的清除方案都能被恶意 SW 反制**；只有「服务器在浏览器内部更新通道上响应什么字节」是攻击者无法干预的。

## 3. 架构

```
config/sw-manifest.json     信任根：合法 SW 清单（URL / scope / 版本 / SHA-256 / 缓存前缀）
src/core/                   清单加载与运行时 hash 校验、共享类型、JSON Schema
src/server/                 Node 原生 HTTP 演示站（三模式）+ 事件取证 + kill SW 渲染 + 安全头
src/client/reconcile.ts     页面侧调和库（esbuild 打包为 public/reconcile.js）
public/sw.js                合法业务 SW（离线 App Shell，缓存前缀 app-v，含攻击缓存兜底清理）
public/sw/kill.js.template  清除用 kill SW（运行时注入清单策略）
public/sw/evil-sw.js        模拟攻击者 SW（仅测试）
public/evil-payload.js      恶意 SW 注入页面的同源载荷（仅测试）
src/audit/                  上线前检测：静态规则引擎 + 线上响应头/hash 审计 CLI + 报告
tests/unit/                 Vitest 单元测试（10）
tests/e2e/                  Playwright 端到端（11），持久化 profile + 服务端模式热切换
```

### 服务端三种运行模式

- `clean`：清单内 URL 下发合法字节，**每次响应前复核 SHA-256**；清单外 SW 请求下发 kill SW 并记录事件。
- `infected`：模拟事故窗口期，`/sw.js` 的浏览器内部请求收到被篡改字节。
- `remediating`：应急 **kill-first** 窗口——即使是清单内合法 URL 也先下发 kill SW，清除潜伏恶意版本与恶意缓存；二次部署切回 `clean` 即恢复合法 SW。

## 4. 清除流程：恶意 SW 为什么拦不住

```
感染访客导航
   │
   ├─ 页面 reconcile 拉取服务端清单（信任根），枚举注册、上报 beacon
   │
   ├─ 触发 update() / 浏览器导航自动更新检查 / CDP updateRegistration
   │        │
   │        ▼  浏览器内部网络栈（恶意 SW 的 fetch 事件收不到）
   │   GET /sw.js  头: Service-Worker: script
   │        │
   │        ▼  服务端比对清单：未知 URL / hash 不符 / remediating 窗口
   │   响应 kill SW 字节（Cache-Control: no-store）
   │        │
   │        ▼  字节变化 → install(skipWaiting) → activate(claim 夺权)
   │   kill SW：
   │     1. 只删恶意前缀/精确名缓存（evil-* 等），受保护前缀 app-v* 原样保留
   │     2. postMessage 广播 swguard:killed，页面清理同源存储
   │     3. registration.unregister() 自注销
   │        │
   │        ▼
   └─ 下一次导航：无控制器 → reconcile 按清单重新注册合法 SW → 离线功能连续可用
```

**离线功能为什么不受影响**：kill SW 的缓存删除是白名单制——清单里所有合法 SW 的 `cachePrefixes`（`app-v`）进入 `protectedPrefixes`，任何删除操作都先判断保护前缀。E2E 用例明确断言清除前后 `/offline.html` 缓存始终可命中。

## 5. 发现与取证（两条不可伪造的视图交叉验证）

1. **服务端日志视图（完整）**：记录所有带 `Service-Worker: script` 头的请求。任何清单外 URL（如 `/uploads/backdoor.js`）立即触发 `unknown-script-request` 事件并下发 kill SW。恶意页面可以在浏览器里隐藏注册，但隐藏不了浏览器发出的内部请求。
2. **页面 beacon 视图（纵深）**：reconcile 上报每个注册的 scope/scriptURL/state 与 CacheStorage 名称，服务端对上报内容做不可信复核，与日志交叉印证。
3. 取证端点：`GET /__swguard/incidents`（脚本请求、beacon、安全事件），`npm run report` 生成汇总。

恶意 SW 能伪造页面内 `fetch('/__swguard/health')` 的响应（E2E 专门验证），但 Playwright/服务端的带外请求与浏览器内部更新通道拿到的始终是源站真相。

## 6. 预防（让下一次投毒无法注册成 SW）

- 页面 CSP 含 **`worker-src 'self'`**：第三方注入脚本无法注册 blob:/data:/跨源 worker（E2E 验证两类均被阻断）。
- SW 脚本响应：`Cache-Control: no-store/max-age=0`、`X-Content-Type-Options: nosniff`、收紧的 worker CSP（`default-src 'none'; script-src 'self'`）。
- 注册强制 `updateViaCache:'none'`；`importScripts` 白名单前缀 + 静态扫描拦截跨源/非白名单导入。
- **SHA-256 pinning 双重校验**：进程启动校验磁盘文件，每次响应前再校验；运行期被篡改则自动改发 kill SW，不把新毒字节推给全网。
- 合法 SW activate 内置已知攻击前缀兜底清理（与清单 `kill.purgeCachePrefixes` 保持一致）。

## 7. 上线前检测工具（CI 门禁）

```bash
# 静态扫描：CI 默认只扫清单登记的可信 SW，error 命中 → 退出码 2 阻断发布
npm run audit -- scan
npm run audit -- scan --json

# 全量审计：连测试用恶意样本一起扫，演示规则命中（教学/红队视角）
npm run audit:all

# 线上巡检：拉取运行站点的 SW，校验 hash / 缓存头 / CSP / nosniff / worker-src
SWGUARD_BASE_URL=https://你的站点 npm run audit -- live
```

静态规则覆盖：`eval/new Function`、跨源 `importScripts`、改写 `navigator.serviceWorker` API、HTML 注入、导航响应重写、通配缓存等。`live` 审计在感染态演示中准确报出 `hash-mismatch`。

## 8. 快速开始

```bash
npm install
npm run build:client
npm run typecheck          # 两套 tsconfig
npm run test:unit          # 10 个单元测试
npm run test:e2e           # 11 个浏览器 E2E（用本机缓存的 Chromium，无需联网下载）

# 手工体验三模式
SWGUARD_MODE=clean       npm run server   # http://127.0.0.1:7777
SWGUARD_MODE=infected    npm run server   # 打开 /infected 点「注册恶意 SW」
SWGUARD_MODE=remediating npm run server   # kill-first 应急窗口
npm run report                              # 查看安全事件汇总
npx tsx scripts/debug-full-chain.ts         # 一条命令跑完感染→清除→恢复并打印每步状态
```

## 9. 测试矩阵（浏览器自动化验证的断言）

| 规格文件 | 验证内容 |
| --- | --- |
| `01-baseline` | 合法 SW 注册/接管/离线缓存、硬化头、注销后 reconcile 自动恢复 |
| `02-kill-chain` | 完整感染→kill-first 清除→二次部署恢复；恶意缓存删除而 app-v 保留；页面 API 被投毒仍能清除；清单外 SW 被识别并下发 kill |
| `03-discovery` | `Service-Worker:script` 头识别、beacon 上报复核、恶意 SW 伪造健康检查但带外真相不受影响 |
| `04-hardening` | CSP 阻断 blob/data worker、全套硬化响应头、清单端点不可缓存且不泄露内部字段 |

## 10. 生产化清单（演示实现 → 真实部署要补的部分）

- `IncidentStore` 的 JSONL 实现换成 SIEM/日志平台，并对 `Service-Worker: script` 请求建实时告警；
- 清单 hash 在 CI 中写死并签名，移除 `FILLED_AT_RUNTIME` 占位回填；
- kill-first 窗口时长按访客更新周期设定（覆盖浏览器节流周期），并配合 `Clear-Site-Data` 做纵深；
- 多 scope 站点为每个 scope 维护独立清单条目与缓存前缀；
- CDN/网关层同步强制 SW 路径的 `no-store` 与 CSP，避免边缘缓存绕过源站策略。
