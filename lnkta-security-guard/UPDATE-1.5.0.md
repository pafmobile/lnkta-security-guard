# Version 1.5.0

Emails are limited to suspicious file findings, executable file changes, important website-code/configuration changes and known unauthorized-connector activity. Routine cache/media churn, ordinary background tasks and scan/setup status remain in the dashboard. Unchanged findings do not repeat daily; a new file change or a recurrence after a complete clear check can alert again.

GitHub updates require a dedicated public release repository, a signed manifest and ZIP, a trusted public key configured in wp-config.php, and explicit enablement in Tools > LNKTA Plugin Updates. Only higher compatible versions with verified signatures and package hashes are accepted. The installation lock does not deliberately block updates, but host filesystem restrictions and WordPress policies still apply.

See the repository README for one-time signing setup and website configuration. Never store private signing keys on WordPress or in source/release assets. A first updater-enabled version must be installed manually. Browser protection settings, session sign-out and guarded salt rotation remain available in Tools. Protected or unsupported wp-config.php files are not unlocked.

Monitoring shares the WordPress/PHP trust boundary. It cannot enforce server ownership, stop server cron, replace malware cleanup or provide independent monitoring. PHP-generated headers do not cover static/cache responses that bypass WordPress. Review the dashboard for incomplete scans even when no email is sent.
