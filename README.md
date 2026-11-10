# LNKTA Security Guard

WordPress security hardening, file-change monitoring, readable threat alerts, browser headers, administrator session controls and verified GitHub updates.

Current source version: **1.5.1**. This repository contains only plugin source, documentation, tests and release tooling. No website credentials, malware samples or signing secrets belong here.

## What the release workflow does

After one-time signing setup, **Actions > Build and publish signed release > Run workflow** tests the source, builds an installable ZIP, signs its metadata and publishes a GitHub Release. Later changes to the main plugin version file on `main` trigger the same process. Update all three version declarations (main plugin, hardening.php and updater.php) together. Prepare multi-file changes on a branch and merge them together; do not push incomplete release changes directly to main. Existing releases are never overwritten. No signing secret means no release is published.

WordPress checks published GitHub Releases, not arbitrary Git commits. An installed site must use the updater-enabled plugin, trust the release public key and enable its automatic-update setting. Read-only deployment permissions or disabled WordPress background updates still prevent installation.

## One-time signing setup

Use your own trusted computer, not the WordPress server. Install Python and its `cryptography` package, then clone this repository:

```sh
git clone https://github.com/pafmobile/lnkta-security-guard.git
cd lnkta-security-guard
python -m pip install cryptography
python tools/setup-signing.py
```

The script saves signing files in your home folder under `.lnkta-release-signing/`, outside the clone. It prints only the **public key**, which is safe to share. Keep the signing files private and back them up securely. Do not upload these files into GitHub source or release assets.

In repository **Settings > Secrets and variables > Actions**:

- Add repository **secret** `LNKTA_RELEASE_SIGNING_KEY`: paste the contents of the locally generated `github-secret.txt`.
- Add repository **variable** `LNKTA_RELEASE_PUBLIC_KEY`: paste the contents of the locally generated `public-key.txt`.

If GitHub CLI is already authenticated with the required repository permissions, `python tools/setup-signing.py --github` sets both without printing the private key. It reuses an existing signing key rather than silently replacing it.

Then run **Actions > Build and publish signed release > Run workflow**. A successful release includes the installation ZIP, `manifest.json` and `release-public-key.txt`. The latter is public; check it matches the key generated on your trusted computer. The private key is never included.

## Connect each WordPress website

Install version **1.5.1** manually once. It includes the official repository and this public signing key:

```
f208f57b47edc12fe9f38ab0386d280c6c9edac27bb3aaf16c07fe08665ba531
```

No wp-config.php edit is required. If update constants were previously configured, ensure they match this key and the official repository; explicit constants take precedence.

Do not paste the private signing key or `github-secret.txt` into WordPress. If configuration is protected, ask the host to add the two constants while retaining its protection.

Open **Tools > LNKTA Plugin Updates**, click **Check GitHub now**, then enable **Automatically install verified releases of this plugin**. The installed copy accepts only higher compatible versions with a valid signature and matching ZIP hash. The first same-version release verifies setup but does not reinstall itself. Updates depend on WordPress scheduled tasks and permitted filesystem access.

## Email behavior

Emails are limited to suspicious file findings, executable files, important code/security-setting changes and evidence of the known unauthorized connector. Routine Breeze cache changes, normal background-task changes, scan progress and setup reminders stay in the dashboard. Unchanged findings do not repeat daily. Legitimate source-code updates can still require review.

## Scope

This plugin cannot enforce server ownership, stop cPanel/server cron jobs, replace malware cleanup or provide tamper-proof monitoring against already compromised PHP. See the included version notes for exact coverage, resource limits, recovery, headers and salt-rotation behavior. Automatic updates are unavailable until the signing setup and site trust configuration are complete.
