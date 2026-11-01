// secure の版。防御を外す受け口を持たない（D-24）。
export const currentDefenses = (): { off: Record<string, string> } | undefined => undefined;
export function startAdmin(_port: number): void {}
