/**
 * 报告查看器：从运行中的演示站拉取 /__swguard/incidents，
 * 汇总「发现了哪些恶意/未知 SW 注册、beacon 上报了什么」。
 * 用法：tsx src/audit/inspect-report.ts [baseUrl]
 */
const baseUrl = process.argv[2] ?? process.env.SWGUARD_BASE_URL ?? 'http://127.0.0.1:7777';

interface IncidentView {
  mode: string;
  scriptRequests: Array<{ at: string; url: string; known: boolean; serviceWorkerHeader: string | null }>;
  beaconReports: Array<{ at: string; reason: string; scriptURL: string; scope: string; state: string }>;
  incidents: Array<{ id: string; at: string; kind: string; detail: Record<string, unknown> }>;
}

const res = await fetch(`${baseUrl}/__swguard/incidents`);
if (!res.ok) {
  console.error(`拉取失败: ${res.status}（站点是否在运行？）`);
  process.exit(1);
}
const data = (await res.json()) as IncidentView;

console.log(`\n==== SW Guard 安全事件汇总（${baseUrl}，mode=${data.mode}）====\n`);

console.log(`浏览器内部 SW 脚本请求: ${data.scriptRequests.length} 条`);
for (const e of data.scriptRequests) {
  console.log(`  ${e.known ? '✔ 已知' : '✘ 未知'}  ${e.url}  [SW:${e.serviceWorkerHeader ?? '-'}]  ${e.at}`);
}

console.log(`\n页面 beacon 上报: ${data.beaconReports.length} 条`);
for (const r of data.beaconReports) {
  console.log(`  [${r.reason}] ${r.scriptURL} scope=${r.scope} state=${r.state} ${r.at}`);
}

console.log(`\n安全事件: ${data.incidents.length} 条`);
for (const i of data.incidents) {
  console.log(`  ✘ ${i.kind}  ${JSON.stringify(i.detail)}`);
}

const unknownCount = data.scriptRequests.filter((e) => !e.known).length +
  data.incidents.filter((i) => i.kind === 'unknown-script-request' || i.kind === 'registration-report').length;
console.log(`\n结论：${unknownCount === 0 ? '未发现异常注册' : `发现 ${unknownCount} 个待处置信号（服务端已对未知脚本下发 kill SW）`}\n`);
