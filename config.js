/* ============================================================
   config.js — GitHub sync settings
   ------------------------------------------------------------
   Fill in testuser and vault-data before
   deploying (or after forking). The app works in local-only
   mode until these are set.
   ============================================================ */
export const SYNC = {
  owner: "YOUR_GITHUB_USERNAME",
  repo: "YOUR_REPO_NAME",
  branch: "main",
};

export const SYNC_ENABLED =
  !SYNC.owner.includes("YOUR_") && !SYNC.repo.includes("YOUR_");
