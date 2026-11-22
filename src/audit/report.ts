import type { AuditReport } from '../core/types.js';

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
} as const;

const SEVERITY_STYLE: Record<string, string> = {
  error: COLORS.red,
  warning: COLORS.yellow,
  info: COLORS.blue,
};

/** 终端可读的审计报告渲染 */
export function renderReport(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`${COLORS.bold}SW Guard 上线前审计报告${COLORS.reset}`);
  lines.push(`${COLORS.gray}生成时间: ${report.generatedAt}${COLORS.reset}`);
  lines.push(`目标: ${report.target}`);
  lines.push(
    `汇总: ${COLORS.red}${report.summary.error} error${COLORS.reset} / ` +
      `${COLORS.yellow}${report.summary.warning} warning${COLORS.reset} / ` +
      `${COLORS.blue}${report.summary.info} info${COLORS.reset}`,
  );
  lines.push('─'.repeat(72));

  if (report.findings.length === 0) {
    lines.push('✔ 未发现问题');
    return lines.join('\n');
  }

  const order: Array<'error' | 'warning' | 'info'> = ['error', 'warning', 'info'];
  for (const severity of order) {
    const items = report.findings.filter((f) => f.severity === severity);
    if (items.length === 0) continue;
    for (const f of items) {
      const color = SEVERITY_STYLE[severity];
      lines.push(`${color}[${severity.toUpperCase()}]${COLORS.reset} ${COLORS.bold}${f.id}${COLORS.reset} ${COLORS.gray}(${f.target})${COLORS.reset}`);
      lines.push(`  问题: ${f.message}`);
      lines.push(`  修复: ${f.remediation}`);
      lines.push('');
    }
  }
  return lines.join('\n');
}

/** 机器可读 JSON（与 --json 输出结构一致，供报告查看器/CI 工件消费） */
export function reportToJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
