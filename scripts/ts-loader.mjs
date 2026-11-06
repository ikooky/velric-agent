// Resolve ".js" imports to sibling ".ts" files so the CLI can run from
// sources without a build step (Node >= 22.13 type stripping).
export const resolve = (specifier, context, next) => {
  if (context.parentURL?.startsWith("file:") && specifier.endsWith(".js")) {
    try {
      return next(specifier.replace(/\.js$/, ".ts"), context, true);
    } catch { /* fall through to normal resolution */ }
  }
  return next(specifier, context);
};
