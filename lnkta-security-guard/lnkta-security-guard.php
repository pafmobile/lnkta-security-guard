<?php
/**
 * Plugin Name: LNKTA Security Guard
 * Description: Local login throttling, executable upload restrictions and security event dashboard. Supplement to server security, not a malware remover.
 * Version: 1.5.0
 * Requires PHP: 7.4
 * Requires at least: 6.0
 * Update URI: https://updates.lnkta.invalid/lnkta-security-guard/
 * License: GPL-2.0-or-later
 */
if (!defined('ABSPATH')) { exit; }
final class LNKTA_Security_Guard {
    private static function table() { global $wpdb; return $wpdb->prefix . 'lnkta_guard'; }
    public static function activate() {
        if (is_multisite()) { wp_die('This version supports single-site WordPress only.'); }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $t = self::table(); $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE $t (
            bucket varchar(64) NOT NULL,
            hits bigint unsigned NOT NULL DEFAULT 0,
            expires bigint unsigned NOT NULL,
            PRIMARY KEY  (bucket),
            KEY expires (expires)
        ) $charset;");
        if (!wp_next_scheduled('lnkta_guard_cleanup')) { wp_schedule_event(time()+3600, 'hourly', 'lnkta_guard_cleanup'); }
    }
    public static function deactivate() { wp_clear_scheduled_hook('lnkta_guard_cleanup'); wp_clear_scheduled_hook('lnkta_guard_integrity'); wp_clear_scheduled_hook('lnkta_guard_integrity_continue'); }
    public static function boot() {
        add_filter('authenticate', array(__CLASS__, 'authenticate'), PHP_INT_MAX, 3);
        add_action('wp_login_failed', array(__CLASS__, 'failed'), 10, 2);
        add_filter('login_errors', function () { return 'Sign-in failed. Check your details or try again later.'; });
        add_filter('wp_handle_upload_prefilter', array(__CLASS__, 'upload'));
        add_filter('wp_handle_sideload_prefilter', array(__CLASS__, 'upload'));
        add_action('user_register', function ($id) { self::event('User created', $id); });
        add_action('set_user_role', function ($id, $role) { self::event('Role set: '.sanitize_key($role), $id); }, 10, 2);
        add_action('add_user_role', function ($id, $role) { self::event('Role added: '.sanitize_key($role), $id); }, 10, 2);
        add_action('remove_user_role', function ($id, $role) { self::event('Role removed: '.sanitize_key($role), $id); }, 10, 2);
        add_action('profile_update', function ($id, $old) { $u = get_userdata($id); if ($u && ($old->user_email !== $u->user_email || $old->user_pass !== $u->user_pass)) { self::event('Email or password changed', $id); } }, 10, 2);
        add_action('lnkta_guard_cleanup', array(__CLASS__, 'cleanup'));
        add_action('admin_menu', function () { add_management_page('LNKTA Security Guard', 'LNKTA Security Guard', 'manage_options', 'lnkta-security-guard', array(__CLASS__, 'page')); });
        add_action('admin_notices', function () { if (current_user_can('manage_options')) { echo '<div class="notice notice-info"><p>LNKTA Security Guard: review account events under Tools → LNKTA Security Guard. Server malware cleanup and 2FA are still required.</p></div>'; } });
    }
    private static function bucket() {
        // Never trust HTTP_X_FORWARDED_FOR/CF_CONNECTING_IP supplied by a client.
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return ''; }
        return hash_hmac('sha256', $ip . '|' . (string) floor(time()/900), wp_salt('auth'));
    }
    public static function authenticate($user, $name, $password) {
        if ($name === '' || $password === '') { return $user; }
        global $wpdb; $key = self::bucket();
        if ($key === '') { return $user; }
        $hits = $wpdb->get_var($wpdb->prepare('SELECT hits FROM '.self::table().' WHERE bucket=%s AND expires>%d', $key, time()));
        if ((int)$hits >= 10) { return new WP_Error('lnkta_rate_limited', 'Too many failed sign-ins. Try again in up to 15 minutes.'); }
        return $user;
    }
    public static function failed($name, $error = null) {
        if ($error instanceof WP_Error && $error->get_error_code() === 'lnkta_rate_limited') { return; }
        global $wpdb; $key = self::bucket(); if ($key === '') { return; }
        // Atomic increments avoid transient races and object-cache inconsistencies.
        $wpdb->query($wpdb->prepare('INSERT INTO '.self::table().' (bucket,hits,expires) VALUES (%s,1,%d) ON DUPLICATE KEY UPDATE hits=LEAST(hits+1,1000000)', $key, (int)(floor(time()/900)+1)*900));
    }
    public static function upload($file) {
        $name = strtolower(str_replace('\\', '/', (string)($file['name'] ?? '')));
        if (preg_match('/(?:^|\.)(?:php[0-9]*|phtml|pht|phar|phps|cgi|pl|py|sh|shtml)(?:\.|$)/i', basename($name)) || in_array(basename($name), array('.htaccess','.user.ini','web.config'), true)) {
            $file['error'] = 'Executable files and server configuration files are not allowed as media uploads.';
        }
        return $file;
    }
    public static function event($kind, $id) {
        // No secrets, raw IPs, email addresses, or passwords stored. Bounded local history.
        $events = get_option('lnkta_guard_events', array());
        if (!is_array($events)) { $events = array(); }
        array_unshift($events, array('time'=>gmdate('c'), 'event'=>$kind, 'subject'=>(int)$id, 'actor'=>get_current_user_id()));
        update_option('lnkta_guard_events', array_slice($events, 0, 100), false);
    }
    public static function cleanup() { global $wpdb; $wpdb->query($wpdb->prepare('DELETE FROM '.self::table().' WHERE expires<%d', time())); }
    public static function page() {
        if (!current_user_can('manage_options')) { return; }
        echo '<div class="wrap"><h1>LNKTA Security Guard</h1><p>10 failed password sign-ins per server-observed IP per fixed 15-minute window. Boundary bursts are possible. No permanent bans; existing sessions and REST application passwords are not blocked. No 2FA or malware scanner is included.</p><p><strong>Proxy requirement:</strong> confirm your hosting provider sets REMOTE_ADDR to the verified visitor IP. If it contains a shared proxy IP, do not use this throttle until the host fixes real-IP handling.</p><p>Executable upload restrictions cover the standard WordPress upload and sideload APIs only. They cannot stop arbitrary filesystem writes or direct execution of planted PHP files.</p>';
        echo '<h2>Account events (latest 100)</h2><p>Informational only; account creation and role changes are recorded, not prevented. This database log is not tamper-proof and concurrent events may overwrite each other. Review regularly and use external audit logging for incident response.</p><table class="widefat"><thead><tr><th>UTC</th><th>Event</th><th>Subject user ID</th><th>Actor user ID (0 = unauthenticated/system)</th></tr></thead><tbody>';
        foreach ((array)get_option('lnkta_guard_events', array()) as $e) {
            echo '<tr><td>'.esc_html($e['time']).'</td><td>'.esc_html($e['event']).'</td><td>'.esc_html((string)$e['subject']).'</td><td>'.esc_html((string)$e['actor']).'</td></tr>';
        }
        echo '</tbody></table><h2>Configuration checks</h2><ul>';
        echo '<li>Dashboard file editor explicitly disabled: '.((defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) ? 'yes' : 'no — set in wp-config.php').'</li>';
        echo '<li>WP_DEBUG: '.((defined('WP_DEBUG') && WP_DEBUG) ? 'enabled — disable for normal production use' : 'disabled').'</li>';
        echo '<li>Upload PHP execution blocking, backups, 2FA and WAF: verify separately with the host.</li></ul></div>';
    }
}
register_activation_hook(__FILE__, array('LNKTA_Security_Guard','activate'));
register_deactivation_hook(__FILE__, array('LNKTA_Security_Guard','deactivate'));
LNKTA_Security_Guard::boot();

require_once __DIR__ . '/hardening.php';

require_once __DIR__ . '/incident.php';

require_once __DIR__ . '/headers.php';

require_once __DIR__ . '/sessions.php';

require_once __DIR__ . '/updater.php';
