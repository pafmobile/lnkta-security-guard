# LNKTA Security Guard

WordPress security hardening, file-change monitoring, readable threat alerts, browser headers, administrator session controls and verified GitHub updates.

Current source version: **1.5.5**. This repository contains only plugin source, documentation, tests and release tooling. No website credentials, malware samples or signing secrets belong here.

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

Version 1.5.2 adds a shared daily cap of **2 alert emails per website by default**. Change **Maximum emails per day** under **Tools > LNKTA Integrity & Hardening** (0 disables emails; maximum 100). The counter uses the WordPress calendar day/timezone, persists across requests and restarts, and applies to every alert subject. Concurrent sends reserve slots atomically. Failed mail attempts also consume a slot to prevent repeated delivery attempts. Changing the setting does not reset the counter. Findings remain visible in the dashboard after the cap; there is no queued email backlog. A database error prevents sending rather than bypassing the cap.

Emails are limited to suspicious file findings, executable files, important code/security-setting changes and evidence of the known unauthorized connector. Routine Breeze cache changes, normal background-task changes, scan progress and setup reminders stay in the dashboard. Unchanged findings do not repeat daily. Legitimate source-code updates can still require review.

## Scope

This plugin cannot enforce server ownership, stop cPanel/server cron jobs, replace malware cleanup or provide tamper-proof monitoring against already compromised PHP. See the included version notes for exact coverage, resource limits, recovery, headers and salt-rotation behavior. Automatic updates are unavailable until the signing setup and site trust configuration are complete.


## Version 1.5.3: fewer false positives

Empty or PHP-comment-only index.php files in uploads/cache remain hashed but do not produce executable-file warnings or change emails. Contents are checked each scan; adding executable code removes the exception. Folders and other PHP files are not broadly trusted. Permission-lock matching now examines PHP code tokens so quoted detection patterns and comments do not flag the scanner itself. Actual paired permission-changing calls still generate review warnings. Code changes to Guard files remain monitored. The shared email cap (default two daily) is retained. This is heuristic detection, not proof that a website is clean.


## Version 1.5.4: account alerts and salt rotation

New account creation, account removal, persisted permission/login-name changes and blocked privilege assignments are eligible for email within the existing shared daily cap. Account reports are retained in the dashboard even when mail is suppressed. Integrity scans compare persisted user records directly, bypassing object caches and write hooks, with a 5,000-record safety bound. Initial accounts remain unverified. An inactive or compromised plugin cannot provide reliable protection; temporary changes between scans can be missed. WordPress mail acceptance is not proof of inbox delivery.

Salt rotation accepts direct single- or double-quoted literals. Missing constants can be generated before the standard WordPress bootstrap only when runtime checks confirm they are not already defined elsewhere. Environment-managed secrets, conditional/custom definitions, protected ownership, symlinks and read-only files remain refused. No automatic rotation takes place on update; the authenticated, password-confirmed button is still required.


## Version 1.5.5: monitoring startup

The integrity schedule and account observation initialize on normal WordPress startup, including after reactivation, without requiring an administrator settings visit. Missing scan schedules are restored. Existing privileged accounts are not approved or modified by this initialization.
