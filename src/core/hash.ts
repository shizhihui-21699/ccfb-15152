import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';

/** 流式计算文件 SHA-256（小写 hex），避免把大脚本整体读进内存 */
export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

export function sha256Buffer(buf: Buffer | string): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * 字节差量对比（用于审计报告）：返回两个脚本的简短差异摘要，
 * 不做语义判断——语义判断交给静态规则引擎。
 */
export function hashEqual(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
