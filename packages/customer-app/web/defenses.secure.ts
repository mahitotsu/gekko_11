// secure の版。画面の防御（G22、G23）は、常に効く（D-24）。
export async function loadDefenses(): Promise<(id: string) => boolean> {
  return () => true;
}
