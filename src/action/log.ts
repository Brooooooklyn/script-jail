// script-jail — src/action/log.ts
//
// Re-export shim. The implementation lives in `../shared/log.ts` so the
// shared layer (consumed by both the action and the macOS CLI) does not
// depend back on `src/action/`. Existing action-side importers
// keep their `./log.js` paths.

export * from '../shared/log.js';
