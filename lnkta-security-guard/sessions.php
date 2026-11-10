<?php
if (!defined('ABSPATH')) { exit; }
final class LNKTA_Guard_Sessions {
    public static function keys() { return array('AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'); }
    public static function boot() {
        add_action('admin_menu',function(){add_management_page('LNKTA Sign-in Security','LNKTA Sign-in Security','manage_options','lnkta-guard-sessions',array(__CLASS__,'page'));});
        add_action('admin_post_lnkta_guard_signout',function(){LNKTA_Guard_Sessions::handle('signout');});
        add_action('admin_post_lnkta_guard_salts',function(){LNKTA_Guard_Sessions::handle('salts');});
        add_filter('login_message',function($message){
            $done=isset($_GET['lnkta_guard_done'])?(string)$_GET['lnkta_guard_done']:'';
            if($done==='signout')$message.='<p class="message">All existing WordPress browser sessions were ended, including yours. Sign in again. Passwords and application passwords were not changed.</p>';
            if($done==='salts')$message.='<p class="message">The eight WordPress security keys and salts were replaced and existing browser sessions ended. Sign in again. Passwords and application passwords were not changed.</p>';
            return $message;
        });
    }
    public static function config_path() {
        $root=rtrim(ABSPATH,'/\\');
        if(file_exists($root.'/wp-config.php'))return $root.'/wp-config.php';
        $parent=dirname($root);
        if(file_exists($parent.'/wp-config.php')&&!file_exists($parent.'/wp-settings.php'))return $parent.'/wp-config.php';
        return false;
    }
    public static function writable_config($path) {
        clearstatcache(true,$path);
        return is_string($path)&&is_file($path)&&!is_link($path)&&realpath($path)===$path&&is_readable($path)&&is_writable($path)&&((fileperms($path)&0222)!==0)&&is_writable(dirname($path));
    }
    /** Parse only eight unique, direct single-quoted literal definitions; never eval config. */
    public static function rewrite($source) {
        if(!function_exists('token_get_all'))throw new RuntimeException('This server cannot safely inspect the configuration. Ask your host to rotate the salts.');
        try{$tokens=token_get_all($source,TOKEN_PARSE);}catch(Throwable $e){throw new RuntimeException('The configuration could not be safely checked. Nothing was changed. Ask your host to review it.');}
        $parts=array();$offset=0;
        foreach($tokens as $token){$text=is_array($token)?$token[1]:$token;if(!is_array($token)||!in_array($token[0],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$parts[]=array('text'=>$text,'id'=>is_array($token)?$token[0]:null,'offset'=>$offset);$offset+=strlen($text);}
        $replacements=array();$old=array();$seen=array();
        foreach($parts as $i=>$p){
            if($p['id']!==T_CONSTANT_ENCAPSED_STRING)continue;
            $literal=$p['text'];$name=substr($literal,1,-1);
            if(!in_array($name,self::keys(),true))continue;
            // A matching quoted key anywhere outside this exact direct define is deliberately unsupported.
            if(isset($seen[$name]))throw new RuntimeException('The security keys appear more than once. Nothing was changed. Ask your host to rotate them.');
            $seen[$name]=true;
            if($literal[0]!=="'"||$i<2||strtolower($parts[$i-2]['text'])!=='define'||$parts[$i-2]['id']!==T_STRING||$parts[$i-1]['text']!=='('||($parts[$i+1]['text']??'')!==','||($parts[$i+2]['id']??null)!==T_CONSTANT_ENCAPSED_STRING||($parts[$i+2]['text'][0]??'')!=="'"||($parts[$i+3]['text']??'')!==')'||($parts[$i+4]['text']??'')!==';')throw new RuntimeException('The security keys use a custom configuration format. Nothing was changed. Ask your host to rotate them.');
            $before=$parts[$i-3]['text']??';';if(!in_array($before,array(';','{','}', '<?php\n'),true)&&($parts[$i-3]['id']??null)!==T_OPEN_TAG)throw new RuntimeException('The security keys use a custom configuration format. Nothing was changed. Ask your host to rotate them.');
            $value=$parts[$i+2]['text'];$old[$name]=preg_replace_callback('/\\\\([\\\\\'])/',function($m){return $m[1];},substr($value,1,-1));
            $replacements[]=array($parts[$i+2]['offset'],strlen($value),"'".bin2hex(random_bytes(64))."'");
        }
        if(count($old)!==8)throw new RuntimeException('All eight standard WordPress security keys could not be found. Nothing was changed. Ask your host to rotate them.');
        // Conditional or function-scoped definitions are unsupported even if syntactically valid.
        $depth=0;
        foreach($parts as $p){if($p['text']==='{')$depth++;if($p['text']==='}')$depth--;if($depth!==0&&$p['id']===T_CONSTANT_ENCAPSED_STRING&&in_array(substr($p['text'],1,-1),self::keys(),true))throw new RuntimeException('The security keys use conditional or custom code. Nothing was changed. Ask your host to rotate them.');}
        usort($replacements,function($a,$b){return $b[0]<=>$a[0];});$new=$source;
        foreach($replacements as $r)$new=substr_replace($new,$r[2],$r[0],$r[1]);
        try{token_get_all($new,TOKEN_PARSE);}catch(Throwable $e){throw new RuntimeException('The new configuration could not be validated. Nothing was changed.');}
        return array('source'=>$new,'old'=>$old);
    }
    public static function rotate($path,$check_active=true) {
        if(!self::writable_config($path))throw new RuntimeException('wp-config.php is protected or cannot be safely replaced. Nothing was changed. Keep its protection enabled and ask your host to rotate the salts.');
        $handle=@fopen($path,'r+b');if(!$handle)throw new RuntimeException('wp-config.php could not be opened safely. Nothing was changed.');
        $tmp=null;$temp=null;
        try{
            if(!flock($handle,LOCK_EX|LOCK_NB))throw new RuntimeException('Another process is using wp-config.php. Try again later. Nothing was changed.');
            $stat=fstat($handle);$source=stream_get_contents($handle,1048577);
            if($source===false||strlen($source)>1048576)throw new RuntimeException('The configuration is too large or could not be read. Nothing was changed.');
            $rewrite=self::rewrite($source);
            if($check_active)foreach($rewrite['old'] as $key=>$value)if(!defined($key)||!is_string(constant($key))||!hash_equals(constant($key),$value))throw new RuntimeException('The active security keys do not match this configuration file. Nothing was changed. Ask your host to rotate them at their actual source.');
            $tmp=dirname($path).'/.lnkta-salts-'.bin2hex(random_bytes(16)).'.php';
            $mask=umask(0077);try{$temp=@fopen($tmp,'x+b');}finally{umask($mask);}
            if(!$temp)throw new RuntimeException('A safe replacement could not be created. Nothing was changed.');
            $newstat=fstat($temp);
            if($newstat['uid']!==$stat['uid']||$newstat['gid']!==$stat['gid'])throw new RuntimeException('The configuration has protected ownership. Nothing was changed. Ask your host to rotate the salts.');
            $new=$rewrite['source'];$written=0;
            while($written<strlen($new)){$n=fwrite($temp,substr($new,$written));if(!$n)throw new RuntimeException('The replacement could not be written fully. Nothing was changed.');$written+=$n;}
            if(!fflush($temp)||(function_exists('fsync')&&!fsync($temp)))throw new RuntimeException('The replacement could not be saved safely. Nothing was changed.');
            if(!@chmod($tmp,$stat['mode']&0777))throw new RuntimeException('File permissions could not be preserved. Nothing was changed.');
            clearstatcache(true,$path);$current=lstat($path);
            if(!$current||$current['ino']!==$stat['ino']||$current['dev']!==$stat['dev']||!hash_equals(hash('sha256',$source),(string)@hash_file('sha256',$path))||!hash_equals(hash('sha256',$new),(string)@hash_file('sha256',$tmp)))throw new RuntimeException('The configuration changed during this operation, or verification failed. No replacement was made.');
            if(!@rename($tmp,$path))throw new RuntimeException('The host prevented replacing wp-config.php. Nothing was changed. Ask your host to rotate the salts.');
            $tmp=null;
            if(function_exists('opcache_invalidate'))@opcache_invalidate($path,true);
            return true;
        }finally{if(is_resource($temp))fclose($temp);if($tmp!==null&&file_exists($tmp))@unlink($tmp);flock($handle,LOCK_UN);fclose($handle);}
    }
    public static function handle($operation) {
        if(($_SERVER['REQUEST_METHOD']??'')!=='POST'||!current_user_can('manage_options')||is_multisite())wp_die('This action requires a single-site administrator.');
        check_admin_referer('lnkta_guard_'.$operation);
        if(empty($_POST['confirm']))wp_die('Please return and confirm that everyone, including you, will be signed out. Nothing was changed.');
        $user=wp_get_current_user();$password=isset($_POST['password'])&&is_string($_POST['password'])?wp_unslash($_POST['password']):'';
        if($password===''||!wp_check_password($password,$user->user_pass,$user->ID))wp_die('Your current administrator password was not accepted. Nothing was changed.');
        if($operation==='salts'){
            if(empty($_POST['backup']))wp_die('Please first save a private configuration backup outside the public website folder. Nothing was changed.');
            $path=self::config_path();
            try{if(!$path)throw new RuntimeException('The standard wp-config.php file could not be found. Nothing was changed. Ask your host to rotate the salts.');self::rotate($path);}
            catch(Throwable $e){wp_die(esc_html($e instanceof RuntimeException?$e->getMessage():'The operation could not be completed safely. Ask your host to check the configuration before retrying.'),'Security keys not changed',array('back_link'=>true));}
        }
        WP_Session_Tokens::destroy_all_for_all_users();
        LNKTA_Security_Guard::event($operation==='salts'?'WordPress security keys rotated; browser sessions ended':'All WordPress browser sessions ended',get_current_user_id());
        wp_logout();
        wp_safe_redirect(add_query_arg('lnkta_guard_done',$operation,wp_login_url()));exit;
    }
    public static function page() {
        if(!current_user_can('manage_options'))return;
        echo '<div class="wrap"><h1>LNKTA Sign-in Security</h1><p>Both actions sign out everyone, including you. They do not change user passwords, revoke application passwords or remove malware. Open forms may need reloading. Connected services that depend on salts may need checking.</p>';
        $path=self::config_path();
        if(!$path||!self::writable_config($path))echo '<div class="notice notice-warning inline"><p><strong>Configuration protected:</strong> wp-config.php is unavailable, protected or not safely writable. The salt button will stop with an alert. Keep protection enabled; ask your host to rotate the salts. Signing everyone out still works.</p></div>';
        foreach(array('signout'=>'Sign everyone out','salts'=>'Rotate WordPress security keys and salts') as $op=>$label){
            echo '<h2>'.esc_html($label).'</h2><p>'.($op==='signout'?'Ends existing WordPress browser sessions without editing any configuration files.':'Replaces only the eight standard security keys in wp-config.php. Custom definitions, protected ownership and read-only files are refused. No permissions are relaxed and no backup is left in the public website folder.').'</p><form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';
            wp_nonce_field('lnkta_guard_'.$op);echo '<input type="hidden" name="action" value="lnkta_guard_'.$op.'"><p><label>Your current administrator password: <input type="password" name="password" autocomplete="current-password" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that everyone, including me, will be signed out.</label></p>';
            if($op==='salts')echo '<p><label><input type="checkbox" name="backup" value="1" required> I have saved a private backup of wp-config.php outside the public website folder.</label></p>';
            submit_button($label,'secondary');echo '</form>';
        }
        echo '<p>Only the standard WordPress wp-config.php is handled, not arbitrary config.php files. New keys are generated locally and never displayed, emailed or sent to an external service. After rotation, verify your website and sign in again. If your host keeps an old configuration in PHP memory, ask it to reset OPcache/restart PHP.</p></div>';
    }
}
LNKTA_Guard_Sessions::boot();
