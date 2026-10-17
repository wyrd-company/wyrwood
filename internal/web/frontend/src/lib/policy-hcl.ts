// ---
// relationships:
//   implements: web-interface
// ---

// This is deliberately a recognizer for the graphical subset, not an HCL
// parser. The raw source is authoritative. A single unrecognized byte makes
// the entire document raw-only; edits replace only the selected source span.
export const capabilities = [
  "create",
  "read",
  "update",
  "delete",
  "list",
  "patch",
  "sudo",
  "deny",
] as const;
export interface PathRule {
  path: string;
  capabilities: string[];
  start: number;
  end: number;
  pathStart: number;
  pathEnd: number;
  capsStart: number;
  capsEnd: number;
}
const quoted = '"(?:[^"\\\\\\r\\n]|\\\\.)*"';
const block = new RegExp(
  `path\\s+(${quoted})\\s*\\{\\s*capabilities\\s*=\\s*(\\[\\s*(?:${quoted}(?:\\s*,\\s*${quoted})*\\s*,?)?\\s*\\])\\s*\\}`,
  "dy",
);
const trivia =
  /(?:\s+|#[^\r\n]*(?:\r?\n|$)|\/\/[^\r\n]*(?:\r?\n|$)|\/\*[\s\S]*?\*\/)+/y;
export function graphicalRules(source: string): PathRule[] | null {
  const rules: PathRule[] = [];
  let offset = 0;
  while (offset < source.length) {
    trivia.lastIndex = offset;
    const skipped = trivia.exec(source);
    if (skipped) offset = trivia.lastIndex;
    if (offset === source.length) break;
    block.lastIndex = offset;
    const match = block.exec(source);
    if (!match) return null;
    try {
      const path: string = JSON.parse(match[1]);
      // HCL templates differ from JSON; single-line inputs also strip decoded
      // CR/LF. Keep both cases in the complete raw editor.
      if (hasPathTemplate(path) || /[\r\n]/.test(path)) return null;
      const caps: string[] = JSON.parse(match[2].replace(/,\s*\]/, "]"));
      if (
        caps.some(
          (cap) => !capabilities.includes(cap as (typeof capabilities)[number]),
        )
      )
        return null;
      const indices = match.indices!;
      rules.push({
        path,
        capabilities: caps,
        start: offset,
        end: block.lastIndex,
        pathStart: indices[1]![0],
        pathEnd: indices[1]![1],
        capsStart: indices[2]![0],
        capsEnd: indices[2]![1],
      });
    } catch {
      return null;
    }
    offset = block.lastIndex;
  }
  return rules;
}
export function replaceSpan(
  source: string,
  start: number,
  end: number,
  value: string,
) {
  return source.slice(0, start) + value + source.slice(end);
}
export function appendRule(source: string, path: string, caps = ["read"]) {
  return (
    source +
    (source && !source.endsWith("\n") ? "\n" : "") +
    `path ${JSON.stringify(path)} { capabilities = ${JSON.stringify(caps)} }\n`
  );
}
export const selfOperations = [
  ["auth/token/lookup-self", "read"],
  ["auth/token/renew-self", "update"],
  ["auth/token/revoke-self", "update"],
] as const;
export function addSelfOperations(source: string) {
  const rules = graphicalRules(source);
  if (!rules) return source;
  for (const [path, cap] of selfOperations) {
    if (
      !rules.some(
        (rule) =>
          rule.path === path &&
          rule.capabilities.includes(cap) &&
          !rule.capabilities.includes("deny"),
      )
    ) {
      source = appendRule(source, path, [cap]);
    }
  }
  return source;
}

export function hasPathTemplate(path: string) {
  return path.includes("${") || path.includes("%{");
}

// KV names are literals; ACL wildcards have no escaping syntax. Do not turn
// a name selected from metadata into a broader policy grant by accident.
export function isLiteralACLPath(path: string) {
  return (
    !path.includes("*") &&
    !path.split("/").includes("+") &&
    !path.includes("{{") &&
    !hasPathTemplate(path)
  );
}
