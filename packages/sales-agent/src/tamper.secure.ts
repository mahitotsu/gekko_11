// secure の版。書き換えの受け口を持たない（D-20）。
export const tampering = (): boolean => false;
export function startAdmin(_port: number): void {}
