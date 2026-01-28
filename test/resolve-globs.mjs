import fg from "fast-glob";

function normalizePattern(pattern) {
  return pattern.replace(/\\/g, "/");
}

export function resolveGlobs(patterns, { cwd = process.cwd() } = {}) {
  const normalized = patterns.map(normalizePattern);
  const entries = fg.sync(normalized, {
    cwd,
    absolute: true,
    onlyFiles: true,
    unique: true,
  });

  entries.sort();
  return entries;
}
