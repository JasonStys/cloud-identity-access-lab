/** Jason Stys: copy only reviewed static assets after strict TypeScript compilation. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * variable: name — line 7
END CODE MAP */
import { mkdir, copyFile } from "node:fs/promises";
await mkdir("dist", { recursive: true });
for (const name of ["index.html", "style.css"])
  await copyFile("web/" + name, "dist/" + name);
