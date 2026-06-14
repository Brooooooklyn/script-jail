// Shape fixture: the main Phase-B install pass observes this `postinstall`
// reading a second protected env var (CI_SECRET). Present so the merged event
// stream carries an event from the MAIN pass as well as the prepare pass,
// making it clear the two passes compose into one lockfile.
const _secret = process.env.CI_SECRET;
if (_secret && _secret.length > 0) {
  // No-op.
}
