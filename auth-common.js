// Shared sign-out behavior for index.html, plan.html, onboarding.html, and
// connect.html. Kept as one file so all four stay in sync rather than
// drifting copies of the same logic.

// Every app-set localStorage key uses this prefix (race date, manual
// workouts, milestones, lift log, etc.) — clearing by prefix means a new
// key added later is covered automatically, with no list to keep updated.
const APP_STORAGE_PREFIX = 'atlas703_';

function clearAppStorage() {
  try {
    Object.keys(localStorage)
      .filter((k) => k.startsWith(APP_STORAGE_PREFIX))
      .forEach((k) => localStorage.removeItem(k));
  } catch (e) {
    // localStorage unavailable (private browsing, etc.) — nothing to clear
  }
  try {
    sessionStorage.removeItem('strava_prefill_first_name');
    sessionStorage.removeItem('strava_prefill_last_name');
  } catch (e) {
    // sessionStorage unavailable — same as above
  }
}

// Always clears local state and lands on connect.html, even if the network
// signOut() call itself fails — on a shared device, leaving stale app data
// behind because of a network blip is worse than a signOut() that didn't
// fully round-trip to the server.
async function signOutEverywhere(sb) {
  try {
    await sb.auth.signOut();
  } catch (e) {
    console.error('signOut failed', e);
  }
  clearAppStorage();
  location.href = 'connect.html';
}
