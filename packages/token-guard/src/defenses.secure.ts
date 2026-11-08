// secure の版。防御を外す受け口を持たない（D-24）。
export const enabled = (_id: string): boolean => true;
export const variant = (_id: string): string | undefined => undefined;
export function startAdmin(_port: number, _known: readonly string[]): void {}
