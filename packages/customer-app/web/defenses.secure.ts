// secure の版。画面の防御（D21〜D23）は、常に効く（D-24）。
export async function loadDefenses(): Promise<(id: string) => boolean> {
  return () => true;
}
