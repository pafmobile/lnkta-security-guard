<?php
if (!defined('ABSPATH')) { exit; }
/** GitHub Releases transport with locally trusted Ed25519 verification. */
final class LNKTA_Guard_Updater {
    const VERSION='1.5.1';
    const DEFAULT_REPOSITORY='pafmobile/lnkta-security-guard';
    const DEFAULT_PUBLIC_KEY='f208f57b47edc12fe9f38ab0386d280c6c9edac27bb3aaf16c07fe08665ba531';
    const UPDATE_ID='https://updates.lnkta.invalid/lnkta-security-guard/';
    public static function file() { return plugin_basename(__DIR__.'/lnkta-security-guard.php'); }
    public static function repository() {
        $r=defined('LNKTA_GUARD_RELEASE_REPOSITORY')?LNKTA_GUARD_RELEASE_REPOSITORY:self::DEFAULT_REPOSITORY;
        return is_string($r)&&preg_match('~^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$~D',$r)?$r:'';
    }
    public static function key() {
        $k=defined('LNKTA_GUARD_RELEASE_PUBLIC_KEY')?LNKTA_GUARD_RELEASE_PUBLIC_KEY:self::DEFAULT_PUBLIC_KEY;
        return is_string($k)&&preg_match('/^[a-f0-9]{64}$/iD',$k)?hex2bin($k):false;
    }
    public static function ready() { return self::repository()!==''&&self::key()!==false&&function_exists('sodium_crypto_sign_verify_detached'); }
    public static function boot() {
        add_filter('update_plugins_updates.lnkta.invalid',array(__CLASS__,'offer'),10,4);
        add_filter('upgrader_pre_download',array(__CLASS__,'download'),10,4);
        add_filter('auto_update_plugin',array(__CLASS__,'automatic'),10,2);
        add_action('admin_menu',function(){add_management_page('LNKTA Plugin Updates','LNKTA Plugin Updates','update_plugins','lnkta-guard-updates',array(__CLASS__,'page'));});
    }
    public static function verify($envelope,$key,$repo) {
        if(!is_array($envelope)||!isset($envelope['payload'],$envelope['signature'])||!is_string($envelope['payload'])||!is_string($envelope['signature'])||!is_string($key)||strlen($key)!==32||!function_exists('sodium_crypto_sign_verify_detached'))return false;
        $payload=base64_decode($envelope['payload'],true);$sig=base64_decode($envelope['signature'],true);
        if(!is_string($payload)||strlen($payload)>16384||!is_string($sig)||strlen($sig)!==64)return false;
        try{if(!sodium_crypto_sign_verify_detached($sig,$payload,$key))return false;}catch(Throwable $e){return false;}
        $m=json_decode($payload,true);
        if(!is_array($m)||($m['repository']??'')!==$repo||($m['slug']??'')!=='lnkta-security-guard')return false;
        foreach(array('version','requires_php','requires_wp') as $f)if(!isset($m[$f])||!is_string($m[$f])||!preg_match('/^\d+\.\d+(?:\.\d+)?$/D',$m[$f]))return false;
        if(!isset($m['sha256'])||!is_string($m['sha256'])||!preg_match('/^[a-f0-9]{64}$/D',$m['sha256']))return false;
        $expected='https://github.com/'.$repo.'/releases/download/v'.$m['version'].'/lnkta-security-guard-v'.$m['version'].'.zip';
        if(($m['package_url']??'')!==$expected)return false;
        return $m;
    }
    public static function manifest($fresh=false) {
        if(!self::ready())return false;
        $cache='lnkta_guard_release_'.substr(hash('sha256',self::repository().bin2hex(self::key())),0,20);
        $envelope=$fresh?false:get_transient($cache);
        if($envelope===false){
            $response=wp_safe_remote_get('https://github.com/'.self::repository().'/releases/latest/download/manifest.json',array('timeout'=>15,'redirection'=>5,'limit_response_size'=>32768,'headers'=>array('Accept'=>'application/json')));
            if(is_wp_error($response)||wp_remote_retrieve_response_code($response)!==200){update_option('lnkta_guard_update_status','Could not fetch the release details. Updates paused; check GitHub availability and whether the repository is public.',false);return false;}
            $envelope=json_decode(wp_remote_retrieve_body($response),true);
        }
        $m=self::verify($envelope,self::key(),self::repository());
        if(!$m){update_option('lnkta_guard_update_status','The release signature or details could not be verified. No update was allowed.',false);return false;}
        set_transient($cache,$envelope,3600);update_option('lnkta_guard_update_status','A signed release was verified: version '.$m['version'].'.',false);return $m;
    }
    public static function compatible($m) { global $wp_version;return version_compare(PHP_VERSION,$m['requires_php'],'>=')&&version_compare((string)$wp_version,$m['requires_wp'],'>='); }
    public static function offer($update,$data,$file,$locales) {
        if($file!==self::file())return $update;
        $m=self::manifest();if(!$m||!self::compatible($m)||!version_compare($m['version'],self::VERSION,'>'))return false;
        return array('id'=>self::UPDATE_ID,'slug'=>'lnkta-security-guard','version'=>$m['version'],'url'=>'https://github.com/'.self::repository().'/releases','package'=>$m['package_url'],'requires'=>$m['requires_wp'],'requires_php'=>$m['requires_php'],'autoupdate'=>(bool)get_option('lnkta_guard_auto_updates',false));
    }
    public static function automatic($update,$item) {
        if(($item->plugin??'')!==self::file())return $update;
        return self::ready()&&(bool)get_option('lnkta_guard_auto_updates',false);
    }
    public static function hash_ok($path,$expected) { return is_file($path)&&hash_equals($expected,(string)hash_file('sha256',$path)); }
    public static function download($reply,$package,$upgrader,$extra) {
        $target=isset($extra['plugin'])&&$extra['plugin']===self::file();
        $repo=self::repository();
        if(!$target&&$repo!==''&&is_string($package)&&strpos($package,'https://github.com/'.$repo.'/releases/download/')===0)$target=true;
        if(!$target)return $reply;
        $m=self::manifest(true);
        if(!$m||$m['package_url']!==$package||!self::compatible($m)||!version_compare($m['version'],self::VERSION,'>'))return new WP_Error('lnkta_update_unverified','The Security Guard update was not verified. No update was installed.');
        if($reply!==false)return new WP_Error('lnkta_update_transport','Another plugin changed the download process. Security Guard stopped this update for verification.');
        if(!function_exists('download_url'))require_once ABSPATH.'wp-admin/includes/file.php';
        $path=download_url($package,300);
        if(is_wp_error($path))return $path;
        if(!self::hash_ok($path,$m['sha256'])){@unlink($path);return new WP_Error('lnkta_update_hash','The downloaded update did not match the signed release. It was discarded.');}
        return $path;
    }
    public static function page() {
        if(!current_user_can('update_plugins'))return;
        if(($_SERVER['REQUEST_METHOD']??'')==='POST'){
            check_admin_referer('lnkta_guard_updates');
            if(isset($_POST['save']))update_option('lnkta_guard_auto_updates',!empty($_POST['automatic'])&&self::ready(),false);
            if(isset($_POST['check'])){self::manifest(true);delete_site_transient('update_plugins');}
            echo '<div class="notice notice-info"><p>Settings saved or check completed. See the status below.</p></div>';
        }
        echo '<div class="wrap"><h1>LNKTA Plugin Updates</h1><p>Installed version: '.esc_html(self::VERSION).'. Updates are downloaded from GitHub Releases and accepted only when their signature and ZIP fingerprint match the trusted release key.</p>';
        if(!self::ready())echo '<div class="notice notice-warning inline"><p>Automatic updates are not connected. This build includes the release repository and public key. Check PHP sodium support and any wp-config.php overrides. No GitHub password or access token is stored in WordPress.</p></div>';
        echo '<p>Repository: '.esc_html(self::repository()?:'Not configured').'</p><p>'.esc_html(get_option('lnkta_guard_update_status','No release has been checked yet.')).'</p><form method="post">';wp_nonce_field('lnkta_guard_updates');
        echo '<p><label><input type="checkbox" name="automatic" value="1" '.(get_option('lnkta_guard_auto_updates')?'checked':'').'> Automatically install verified releases of this plugin</label></p>';
        submit_button('Save update setting','secondary','save',false);echo ' ';submit_button('Check GitHub now','secondary','check',false);echo '</form><p>Updates use WordPress’s normal background updater and depend on working scheduled tasks and filesystem permissions. If PHP cannot write plugin code, keep that protection: your host/deployment account must apply updates instead. Creating a ZIP in ChatGPT does not publish a GitHub release.</p><p>The official repository and public signing key are included. No wp-config.php edit is required. Explicit hosting constants <code>LNKTA_GUARD_RELEASE_REPOSITORY</code> and <code>LNKTA_GUARD_RELEASE_PUBLIC_KEY</code> override these defaults. See UPDATE-1.5.0.md for the release procedure. Never put the private signing key on the website or in the repository.</p></div>';
    }
}
LNKTA_Guard_Updater::boot();
