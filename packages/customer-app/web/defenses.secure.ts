// secure の版。画面の防御（G22、G23）は、常に効く（D-24）。防御を外せる複製の帯も出さない。
import type { Defenses } from "./defense-state.ts";

export async function loadDefenses(): Promise<Defenses> {
  return { enabled: () => true };
}
