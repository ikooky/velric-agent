import { ALL_CONTRACTS } from "../dist/contracts/contracts.js";
import { readFile } from "node:fs/promises";

const golden = JSON.parse(await readFile(new URL("../tests/golden_samples.json", import.meta.url), "utf8"));
let stripped = 0;
for (const [tool, sample] of Object.entries(golden.samples)) {
  const c = ALL_CONTRACTS.find((x) => x.name === tool);
  if (!c) continue;
  const p = c.outputSchema.safeParse(sample);
  if (!p.success) { console.log("REJECT", tool); continue; }
  const before = JSON.stringify(sample);
  const after = JSON.stringify(p.data);
  if (before !== after) {
    stripped++;
    const b = sample, a = p.data;
    const removed = Object.keys(b).filter((k) => !(k in a));
    console.log("STRIP", tool, "->", removed.join(","));
  }
}
console.log("total stripped:", stripped);
