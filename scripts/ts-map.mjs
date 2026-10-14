/** Jason Stys: exact AST declaration/parameter maps for TypeScript/JavaScript and static HTML/CSS control maps. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * definition: strip — line 38
 * parameter: source — line 38
 * definition: mapped — line 44
 * parameter: source — line 44
 * parameter: path — line 44
 * variable: records — line 46
 * variable: insertion — line 47
 * variable: offset — line 48
 * variable: tree — line 50
 * definition: visit — line 58
 * parameter: node — line 58
 * variable: kind — line 68
 * variable: [index, line] — line 85
 * variable: pattern — line 86
 * variable: match — line 89
 * variable: count — line 97
 * variable: body — line 98
 * parameter: [kind, name, line] — line 100
 * variable: html — line 104
 * variable: header — line 105
 * definition: main — line 110
 * variable: paths — line 111
 * parameter: folder — line 114
 * parameter: name — line 116
 * parameter: name — line 117
 * parameter: lists — line 119
 * variable: stale — line 121
 * variable: path — line 122
 * variable: source — line 123
 * variable: expected — line 124
END CODE MAP */
import ts from "typescript";
import { readFile, writeFile, readdir } from "node:fs/promises";

/** Remove only the generated map, preserving module purpose descriptions and executable source. */
function strip(source) {
  return source
    .replace(/\/\* BEGIN CODE MAP[\s\S]*?END CODE MAP \*\/\n/g, "")
    .replace(/<!-- BEGIN CODE MAP[\s\S]*?END CODE MAP -->\n/g, "");
}
/** Use the compiler AST for named definitions, bindings and parameters rather than guessing with text search. */
function mapped(source, path) {
  source = strip(source);
  const records = [];
  const insertion = source.indexOf("\n") + 1;
  const offset = source.slice(0, insertion).split("\n").length - 1;
  if (/\.(ts|mjs)$/.test(path)) {
    const tree = ts.createSourceFile(
      path,
      source,
      ts.ScriptTarget.Latest,
      true,
      path.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS,
    );
    /** Visit every declaration recursively; nested destructured names remain represented by their source spelling. */
    function visit(node) {
      if (
        (ts.isFunctionDeclaration(node) ||
          ts.isClassDeclaration(node) ||
          ts.isInterfaceDeclaration(node) ||
          ts.isVariableDeclaration(node) ||
          ts.isParameter(node) ||
          ts.isPropertySignature(node)) &&
        node.name
      ) {
        const kind = ts.isParameter(node)
          ? "parameter"
          : ts.isVariableDeclaration(node)
            ? "variable"
            : ts.isPropertySignature(node)
              ? "field"
              : "definition";
        records.push([
          kind,
          node.name.getText(tree).replace(/\s+/g, " "),
          tree.getLineAndCharacterOfPosition(node.getStart(tree)).line + 1,
        ]);
      }
      ts.forEachChild(node, visit);
    }
    visit(tree);
  } else {
    for (const [index, line] of source.split("\n").entries()) {
      const pattern = path.endsWith(".html")
        ? /\bid="([^"]+)"/g
        : /--([a-z-]+)\s*:/g;
      for (const match of line.matchAll(pattern))
        records.push([
          path.endsWith(".html") ? "control" : "variable",
          match[1],
          index + 1,
        ]);
    }
  }
  const count = records.length + 2;
  const body = records
    .map(
      ([kind, name, line]) =>
        ` * ${kind}: ${name} — line ${line > offset ? line + count : line}`,
    )
    .join("\n");
  const html = path.endsWith(".html");
  const header = `${html ? "<!--" : "/*"} BEGIN CODE MAP (generated; npm run code-map)\n${body}${body ? "\n" : ""}END CODE MAP ${html ? "-->" : "*/"}\n`;
  return source.slice(0, insertion) + header + source.slice(insertion);
}

/** Check or regenerate the complete authored browser/build/test map set; dist and node_modules are excluded. */
async function main() {
  const paths = [
    "playwright.config.mjs",
    ...(await Promise.all(
      ["web", "scripts", "tests/ui", "tests/e2e"].map(async (folder) =>
        (await readdir(folder))
          .filter((name) => /\.(ts|mjs|html|css)$/.test(name))
          .map((name) => `${folder}/${name}`),
      ),
    ).then((lists) => lists.flat())),
  ];
  let stale = false;
  for (const path of paths) {
    const source = await readFile(path, "utf8");
    const expected = mapped(source, path);
    if (source !== expected) {
      stale = true;
      if (!process.argv.includes("--check")) await writeFile(path, expected);
    }
  }
  if (stale && process.argv.includes("--check"))
    throw new Error("Browser/build/test code maps stale");
  console.log(`Browser code maps current: ${paths.length} files`);
}
await main();
