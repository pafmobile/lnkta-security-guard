<?php
if (!defined('ABSPATH')) { exit; }
/** PHP-only header delivery; no server files are written. */
final class LNKTA_Guard_Headers {
    public static function defaults() {
        return array('enabled'=>true,'nosniff'=>true,'referrer'=>true,'legacy'=>true,'frame'=>false,'hsts'=>false,'hsts_age'=>86400,'hsts_subdomains'=>false,'permissions'=>false,'permissions_value'=>'camera=(), microphone=(), geolocation=()','csp_mode'=>'off','csp_value'=>"base-uri 'self'; object-src 'none'; frame-ancestors 'self'");
    }
    public static function options() { return self::sanitize((array)get_option('lnkta_guard_headers',self::defaults())); }
    public static function safe_value($v) { return is_string($v) && strlen($v)<=8192 && !preg_match('/[^\x20-\x7e]/',$v); }
    public static function sanitize($raw) {
        $out=self::defaults();
        foreach(array('enabled','nosniff','referrer','legacy','frame','hsts','hsts_subdomains','permissions') as $key) $out[$key]=!empty($raw[$key]);
        $age=isset($raw['hsts_age'])?(int)$raw['hsts_age']:86400;
        $out['hsts_age']=in_array($age,array(0,86400,604800,2592000,31536000),true)?$age:86400;
        $out['csp_mode']=isset($raw['csp_mode']) && in_array($raw['csp_mode'],array('off','report','enforce'),true)?$raw['csp_mode']:'off';
        foreach(array('csp_value','permissions_value') as $key) if(isset($raw[$key]) && self::safe_value($raw[$key])) $out[$key]=trim($raw[$key]);
        return $out;
    }
    public static function boot() {
        add_action('init',array(__CLASS__,'send'),0);
        add_action('admin_init',array(__CLASS__,'send'),999);
        add_action('login_init',array(__CLASS__,'send'),999);
        add_action('send_headers',array(__CLASS__,'send'),999);
        add_action('template_redirect',function(){ LNKTA_Guard_Headers::send(true); },-1000);
        add_filter('rest_pre_serve_request',function($served){ LNKTA_Guard_Headers::send();return $served; },999);
        add_filter('wp_headers',array(__CLASS__,'filter_headers'),PHP_INT_MAX);
        add_action('admin_menu',function(){add_management_page('LNKTA Browser Protection','LNKTA Browser Protection','manage_options','lnkta-guard-headers',array(__CLASS__,'page'));});
    }
    public static function build($options,$https,$frontend=false) {
        $o=self::sanitize($options);$h=array();
        if(!$o['enabled'] || (defined('LNKTA_GUARD_DISABLE_HEADERS') && LNKTA_GUARD_DISABLE_HEADERS)) return $h;
        if($o['nosniff']) $h['X-Content-Type-Options']='nosniff';
        if($o['referrer']) $h['Referrer-Policy']='strict-origin-when-cross-origin';
        if($o['legacy']) $h['X-Permitted-Cross-Domain-Policies']='none';
        if($o['frame']) $h['X-Frame-Options']='SAMEORIGIN';
        if($o['hsts'] && $https) $h['Strict-Transport-Security']='max-age='.$o['hsts_age'].($o['hsts_subdomains']?'; includeSubDomains':'');
        if($frontend && $o['permissions'] && $o['permissions_value']!=='') $h['Permissions-Policy']=$o['permissions_value'];
        if($frontend && $o['csp_mode']!=='off' && $o['csp_value']!=='') $h[$o['csp_mode']==='report'?'Content-Security-Policy-Report-Only':'Content-Security-Policy']=$o['csp_value'];
        return $h;
    }
    public static function merge($existing,$desired) {
        $names=array_map('strtolower',array_keys($existing));
        foreach($desired as $name=>$value) if(!in_array(strtolower($name),$names,true)) $existing[$name]=$value;
        return $existing;
    }
    public static function filter_headers($headers) {
        $frontend=!is_admin() && !(defined('REST_REQUEST') && REST_REQUEST) && (($GLOBALS['pagenow']??'')!=='wp-login.php');
        return self::merge($headers,self::build(self::options(),is_ssl(),$frontend));
    }
    public static function send($frontend=false) {
        if(headers_sent()) return;
        $frontend=$frontend===true && !is_admin() && !(defined('REST_REQUEST') && REST_REQUEST) && (($GLOBALS['pagenow']??'')!=='wp-login.php');
        $existing=array();
        foreach(headers_list() as $line) { $parts=explode(':',$line,2);if(count($parts)===2)$existing[strtolower(trim($parts[0]))]=true; }
        foreach(self::build(self::options(),is_ssl(),$frontend) as $name=>$value) if(!isset($existing[strtolower($name)])) header($name.': '.$value,true);
    }
    public static function page() {
        if(!current_user_can('manage_options')) return;
        $o=self::options();
        if(($_SERVER['REQUEST_METHOD']??'')==='POST') {
            check_admin_referer('lnkta_headers');
            $raw=isset($_POST['headers'])&&is_array($_POST['headers'])?wp_unslash($_POST['headers']):array();
            $valid=true;
            foreach(array('csp_value','permissions_value') as $key) if(isset($raw[$key])&&!self::safe_value($raw[$key]))$valid=false;
            if($valid) { $o=self::sanitize($raw);update_option('lnkta_guard_headers',$o,false);echo '<div class="notice notice-success"><p>Saved. Clear your website/CDN cache and check the public response headers. These settings apply to subsequent requests.</p></div>'; }
            else echo '<div class="notice notice-error"><p>Not saved. Policies must be a single line of plain text, at most 8192 characters, without line breaks or special control characters.</p></div>';
        }
        echo '<div class="wrap"><h1>LNKTA Browser Protection</h1><p>These settings tell visitors’ browsers to handle your website more safely. They work through WordPress/PHP on Apache and Nginx. They do not remove malware, prevent PHP file creation, or block server cron jobs.</p><p><strong>Coverage:</strong> WordPress pages, login, admin and REST responses that load this plugin before output. Static images, server/CDN cache hits and early cache drop-ins may bypass it. Ask your host to cover those responses.</p><p>Use one header manager. Existing PHP headers are preserved where visible; headers added later by your host or CDN cannot be detected here. This plugin never edits .htaccess or Nginx configuration.</p><form method="post">';wp_nonce_field('lnkta_headers');
        $labels=array('enabled'=>'Enable browser protection headers','nosniff'=>'Prevent browsers from guessing executable file types','referrer'=>'Limit information shared when visitors follow external links','legacy'=>'Disable legacy cross-domain policy files','frame'=>'Allow embedding this site only within this same website (may stop external embeds)','hsts'=>'Tell browsers to use HTTPS only (enable after confirming reliable HTTPS)','hsts_subdomains'=>'Apply HTTPS-only protection to every subdomain (all must support HTTPS)','permissions'=>'Restrict browser features on public pages using the policy below');
        foreach($labels as $key=>$label) echo '<p><label><input type="checkbox" name="headers['.esc_attr($key).']" value="1" '.($o[$key]?'checked':'').'> '.esc_html($label).'</label></p>';
        echo '<p><label>How long browsers remember HTTPS-only protection: <select name="headers[hsts_age]">';
        foreach(array(0=>'Clear the remembered rule',86400=>'1 day (start here)',604800=>'1 week',2592000=>'30 days',31536000=>'1 year') as $value=>$label)echo '<option value="'.(int)$value.'" '.($o['hsts_age']===$value?'selected':'').'>'.esc_html($label).'</option>';
        echo '</select></label></p><p>HSTS is sent only when WordPress recognizes HTTPS. No preload registration is added. Turning the setting off does not erase a rule already remembered by a browser: to clear it, keep HSTS enabled and choose “Clear the remembered rule” over HTTPS. A host/CDN rule must be changed at its own source. Behind a proxy, ask your host to configure trustworthy HTTPS detection.</p>';
        echo '<p><label>Browser features policy (advanced):<br><input class="large-text" name="headers[permissions_value]" value="'.esc_attr($o['permissions_value']).'"></label><br>The suggested policy disables camera, microphone and location access. Leave this protection off if your site needs these features.</p>';
        echo '<h2>Control which content can load (advanced)</h2><p>A content policy can break scripts, embeds or forms if it does not match your website. Start in test mode. The suggested policy is limited protection, not a complete script/XSS policy.</p><p><select name="headers[csp_mode]">';
        foreach(array('off'=>'Off','report'=>'Test only — browser console warnings; nothing blocked','enforce'=>'Enforce — browser blocks content that violates the policy') as $value=>$label)echo '<option value="'.esc_attr($value).'" '.($o['csp_mode']===$value?'selected':'').'>'.esc_html($label).'</option>';
        echo '</select></p><textarea class="large-text" rows="3" name="headers[csp_value]">'.esc_textarea($o['csp_value']).'</textarea><p>The policy applies only to public WordPress pages. Test mode sends no reports to the plugin; review browser developer tools. No policy is forced on the admin, login or REST API.</p>';
        submit_button('Save browser protection');echo '</form><p>Emergency switch through trusted hosting access: <code>define(\'LNKTA_GUARD_DISABLE_HEADERS\', true);</code> in wp-config.php. This stops this module’s headers; server settings and browser-remembered HTTPS rules remain.</p></div>';
    }
}
LNKTA_Guard_Headers::boot();
