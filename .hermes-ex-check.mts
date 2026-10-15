
import { ALL_CONTRACTS } from "./src/contracts/contracts.ts";
let fails = [];
for (const c of ALL_CONTRACTS) {
  for (const ex of c.examples ?? []) {
    const r = c.inputSchema.safeParse(ex.input);
    if (!r.success) fails.push(c.name + " :: " + ex.title + " :: " + r.error.issues.map(i=>i.path.join(".")+" "+i.message).join("; "));
  }
}
console.log("contracts:", ALL_CONTRACTS.length);
console.log("example fails:", fails.length);
for (const f of fails) console.log("FAIL", f);
