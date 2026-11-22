import { mkdir, appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { SecurityIncident } from '../core/types.js';

/**
 * 安全事件存储（演示实现：JSONL 追加写）。
 * 生产环境应替换为 SIEM / 日志平台，但接口保持不变。
 */
export class IncidentStore {
  constructor(private readonly file: string) {}

  async record(kind: SecurityIncident['kind'], detail: Record<string, unknown>): Promise<SecurityIncident> {
    await mkdir(dirname(this.file), { recursive: true });
    const incident: SecurityIncident = {
      id: `inc_${(await this.count()) + 1}_${Date.now().toString(36)}`,
      at: new Date().toISOString(),
      kind,
      detail,
    };
    await appendFile(this.file, JSON.stringify(incident) + '\n', 'utf8');
    return incident;
  }

  async all(): Promise<SecurityIncident[]> {
    try {
      const text = await readFile(this.file, 'utf8');
      return text
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as SecurityIncident);
    } catch {
      return [];
    }
  }

  async count(): Promise<number> {
    return (await this.all()).length;
  }

  async reset(): Promise<void> {
    await writeFile(this.file, '', 'utf8');
  }
}
