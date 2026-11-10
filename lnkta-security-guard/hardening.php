<?php
if (!defined('ABSPATH')) { exit; }
final class LNKTA_Guard_Hardening {
    const VERSION = '1.5.1';
    public static function maintenance() { return defined('LNKTA_GUARD_MAINTENANCE') && LNKTA_GUARD_MAINTENANCE === true; }
    public static function boot() {
        add_filter('rest_pre_dispatch', array(__CLASS__, 'rest'), 999, 3);
        add_filter('rest_endpoints', array(__CLASS__, 'endpoints'), 999);
        add_filter('wp_sitemaps_add_provider', function($provider,$name) { return $name==='users'?false:$provider; },999,2);
        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('xmlrpc_methods', function($methods) { unset($methods['system.multicall'],$methods['pingback.ping'],$methods['pingback.extensions.getPingbacks']); return $methods; });
        add_action('template_redirect', array(__CLASS__, 'author_probe'), -999);
        add_filter('wp_headers', function($headers) { unset($headers['X-Pingback']); return $headers; });
        add_filter('map_meta_cap', array(__CLASS__, 'caps'), 999, 4);
        add_action('set_user_role', array(__CLASS__, 'guard_role'), 999, 2);
        add_action('add_user_role', array(__CLASS__, 'guard_role'), 999, 2);
        add_action('user_register', function($id) { self::notice('User account created', array('User ID: '.(int)$id)); }, 999);
        add_action('lnkta_guard_integrity', array(__CLASS__, 'scan'));
        add_action('lnkta_guard_integrity_continue', array(__CLASS__, 'scan'));
        add_action('admin_init', array(__CLASS__, 'setup'));
        add_action('admin_menu', function() { add_management_page('LNKTA Integrity & Hardening','LNKTA Integrity & Hardening','manage_options','lnkta-guard-integrity',array(__CLASS__,'page')); });
        add_action('admin_notices', function() { if(current_user_can('manage_options') && get_option('lnkta_guard_integrity_alert')) echo '<div class="notice notice-error"><p>LNKTA Security Guard detected file changes or an incomplete scan. Review Tools → LNKTA Integrity & Hardening.</p></div>'; });
    }
    public static function user_route($route) { return (bool)preg_match('~^/wp/v2/users(?:/|$)~i', '/'.ltrim(rawurldecode($route),'/')); }
    public static function rest($result,$server,$request) {
        if(!is_user_logged_in() && self::user_route($request->get_route())) return new WP_Error('lnkta_users_private','User directory access requires authentication.',array('status'=>403));
        return $result;
    }
    public static function endpoints($routes) {
        if(!is_user_logged_in()) foreach(array_keys($routes) as $route) if(self::user_route($route)) unset($routes[$route]);
        return $routes;
    }
    public static function author_probe() {
        // Keep pretty author/member archives and author_name routes available.
        if(!is_user_logged_in() && array_key_exists('author',$_GET)) {
            nocache_headers(); status_header(404);
            wp_die('Page not found.','Not found',array('response'=>404));
        }
    }
    public static function caps($caps,$cap,$id,$args) {
        if(!self::maintenance() && in_array($cap,array('install_plugins','upload_plugins','install_themes','upload_themes','edit_plugins','edit_themes'),true)) return array('do_not_allow');
        return $caps;
    }
    public static function privileged($role) {
        $r=get_role($role); if(!$r) return false;
        foreach(array('manage_options','install_plugins','edit_plugins','edit_users','promote_users','create_users') as $cap) if(!empty($r->capabilities[$cap])) return true;
        return false;
    }
    public static function guard_role($id,$role) {
        static $busy=false;
        if($busy || !$role || !self::privileged($role)) return;
        $approved=(array)get_option('lnkta_guard_privileged_baseline',array());
        if(in_array($role,(array)($approved[(string)$id]??array()),true)) return;
        if(self::maintenance()) {
            $approved[(string)$id][]=$role; update_option('lnkta_guard_privileged_baseline',$approved,false);
            self::notice('Privileged role approved in maintenance mode',array('User ID: '.(int)$id,'Role: '.sanitize_key($role))); return;
        }
        $busy=true; $u=get_userdata($id);
        if($u) { $u->remove_role($role); if(!$u->roles) $u->set_role('subscriber'); }
        if(class_exists('WP_Session_Tokens')) WP_Session_Tokens::get_instance($id)->destroy_all();
        $busy=false;
        self::notice('Blocked privileged role assignment',array('User ID: '.(int)$id,'Role: '.sanitize_key($role)));
    }
    public static function setup() {
        if(!current_user_can('manage_options')) return;
        if(get_option('lnkta_guard_hardening_version')===self::VERSION) return;
        // Existing accounts are inventoried, not certified as trustworthy.
        if(get_option('lnkta_guard_privileged_baseline',null)===null) {
            $approved=array();
            foreach(get_users(array('number'=>1000)) as $u) foreach($u->roles as $r) if(self::privileged($r)) $approved[(string)$u->ID][]=$r;
            update_option('lnkta_guard_privileged_baseline',$approved,false);
        }
        if(!get_option('lnkta_guard_alert_email')) update_option('lnkta_guard_alert_email',sanitize_email(get_option('admin_email')),false);
        if(!wp_next_scheduled('lnkta_guard_integrity')) wp_schedule_event(time()+300,'hourly','lnkta_guard_integrity');
        update_option('lnkta_guard_hardening_version',self::VERSION,false);
    }
    public static function notice($subject,$details,$scan_signature=null) {
        $original_subject=$subject;
        // Email is reserved for file-based suspicions and the known unwanted connector.
        $email_allowed=in_array($subject,array('Suspicious files need review','Website files have changed','Blocked connector activation entry','Blocked connector WordPress scheduled event','Connector persistence requires host cleanup'),true);
        $messages=array(
            'User account created'=>array('A new account was created','The plugin recorded a new website account. This alone does not mean it is unauthorized.','Recorded the event and sent this notification.','Check the account if you did not expect a new registration.'),
            'Privileged role approved in maintenance mode'=>array('An account received extra website permissions','An account was given elevated permissions while maintenance mode was enabled.','Allowed the change because maintenance mode was enabled.','Confirm that you authorized it and turn maintenance mode off when finished.'),
            'Blocked privileged role assignment'=>array('An unexpected permission change was blocked','An account was given elevated permissions that were not previously approved. This could also be an intentional administrator action.','Removed the unapproved role and ended that account’s existing login sessions.','Review the account and recent administrator activity.'),
            'Blocked connector activation entry'=>array('The unwanted connector was prevented from activating','Something tried to add Content Sync Connector to the active plugin list.','Removed its entry from the new active plugin list. Other copies or already running code may remain.','Ask your host to check for remaining connector files and recovery tasks.'),
            'Blocked connector WordPress scheduled event'=>array('A task belonging to the unwanted connector was blocked','Something tried to schedule a task used by Content Sync Connector.','Prevented this WordPress task from being scheduled. Server cron jobs are separate and are not controlled by this plugin.','Ask your host to check for remaining connector loaders and server cron jobs.'),
            'WordPress cron inventory changed'=>array('Website background tasks changed','A background task was added, removed, or changed. Plugin updates and normal website activity can cause this; it is not proof of an attack.','Recorded the change. No tasks were deleted or blocked by this notification.','If no maintenance or plugin activity was expected, review the task names below with your developer.'),
            'Connector persistence requires host cleanup'=>array('Traces of the unwanted connector need review','Settings or tasks associated with Content Sync Connector were found. These may be leftovers; they do not by themselves prove that the connector is running.','Recorded the findings. Nothing was removed automatically.','Ask your host to inspect the listed settings and tasks and finish the cleanup.')
        );
        if(isset($messages[$subject])) {
            $m=$messages[$subject];$subject=$m[0];
            $details=array_merge(array('What was found: '.$m[1],'What the plugin did: '.$m[2],'What you should do: '.$m[3],'Details:'),array_map(array(__CLASS__,'readable_detail'),$details));
        }
        $details=array_slice(array_map('sanitize_text_field',$details),0,70);
        LNKTA_Security_Guard::event($subject,0);
        if(!$email_allowed) return false;
        $fingerprint=$scan_signature!==null?$scan_signature:hash('sha256',$subject.implode('|',$details));
        $mail_key=$scan_signature!==null?'lnkta_guard_last_email_file_scan':'lnkta_guard_last_email_'.hash('sha256',$original_subject);
        // Do not repeat an unchanged finding every day. A changed finding can alert again.
        if(get_option($mail_key) === $fingerprint) return false;
        $email=get_option('lnkta_guard_alert_email');
        if(is_email($email)) {
            $sent=wp_mail($email,'[LNKTA Security] '.$subject,
                'Website: '.home_url('/')."\nChecked at: ".gmdate('Y-m-d H:i').' UTC'."\n\n".implode("\n\n",$details).
                "\n\nView the report: ".home_url('/wp-admin/tools.php?page=lnkta-guard-integrity'));
            if($sent) update_option($mail_key,$fingerprint,false);
            return (bool)$sent;
        }
    }
    public static function readable_detail($line) {
        $replace=array(
            'ADDED '=>'New file or folder: ', 'CHANGED '=>'Changed file or permissions: ', 'REMOVED '=>'Removed file or folder: ',
            'Connector persistence marker '=>'Code matching the unwanted connector was found (needs review): ',
            'Known connector path requires review: '=>'A file or folder associated with the unwanted connector was found: ',
            'Executable file in writable directory (review; may be legitimate): '=>'A file that can contain executable code was found in uploads or cache (may be legitimate): ',
            'Connector database option present: '=>'Saved website setting associated with the unwanted connector: ',
            'Existing connector cron hook: '=>'Existing background task associated with the unwanted connector: ',
            'Connector remains active: hosting cleanup required'=>'The unwanted connector is still listed as active. Hosting cleanup is needed.',
            'Incident-associated path (review provenance): '=>'A filename matching the earlier suspicious files was found (needs review): ',
            'Permission-lock pattern from supplied db-helper sample: '=>'Code that changes file permissions matches the earlier suspicious sample: ',
            'Hook: '=>'Task name: ', 'Added/changed: '=>'New or changed task names: ', 'Removed/changed: '=>'Removed or changed task names: ',
            'Normal plugin activity may cause changes. OS/cPanel cron is not covered.'=>'These are WordPress tasks. Server/cPanel scheduled tasks are not checked here.'
        );
        foreach($replace as $from=>$to) if(strpos($line,$from)===0) return $to.substr($line,strlen($from));
        return $line;
    }
    public static function email_changes($changes) {
        $out=array();
        foreach($changes as $line) {
            if(!preg_match('~^(?:ADDED|CHANGED|REMOVED) (.+)$~',$line,$m)) continue;
            $path=$m[1];
            // Cache/media directory churn is routine. Do not suppress executable payloads.
            if(strpos($path,'/@directory')!==false) continue;
            if(preg_match('~^(?:cache|uploads)/~',$path)) {
                if(preg_match('/\.(?:php[0-9]*|phtml|pht|phar|phps)(?:[.\/]|$)/i',$path) || in_array(basename($path),array('.htaccess','.user.ini','php.ini'),true))$out[]=$line;
            } elseif(preg_match('~^(?:plugins|mu-plugins|themes|root)/~',$path) && (preg_match('/\.(?:php[0-9]*|phtml|pht|phar|phps|js|html|htm)$/i',$path) || in_array(basename($path),array('.htaccess','.user.ini','php.ini'),true))) $out[]=$line;
        }
        return $out;
    }
    public static function scan_message($result,$differences,$first,$reviewed) {
        $differences=self::email_changes($differences);
        $alert_findings=(array)$result['indicators'];
        if(!$alert_findings && !$differences) {
            // Only a completed check can resolve the previous file notification.
            if(!empty($result['complete']) && empty($result['errors'])) delete_option('lnkta_guard_last_email_file_scan');
            return;
        }
        $affected=array();
        foreach($differences as $line) { $path=substr($line,strpos($line,' ')+1);$affected[$path]=$result['files'][$path]??'removed'; }
        foreach($alert_findings as $line) { $pos=strrpos($line,': ');if($pos!==false){$path=substr($line,$pos+2);$affected[$path]=$result['files'][$path]??'finding';} }
        sort($alert_findings);sort($differences);ksort($affected);
        $signature=hash('sha256',serialize(array($alert_findings,$differences,$affected)));
        $problems=!empty($result['errors']);$pending=empty($result['complete']);
        $findings=(array)$result['indicators'];
        $subject=$findings?'Suspicious files need review':'Website files have changed';
        $details=array('What the plugin checked: Selected website code and settings files, including plugins, themes, and executable files in uploads and cache. Files checked so far: '.count($result['files']).'.');
        if($findings) {
            $details[]='What was found: '.count($findings).' warning(s) need review. These signs do not prove that every listed file is malware.';
            foreach(array_slice($findings,0,20) as $line) $details[]=self::readable_detail($line);
        } else $details[]='What was found: No suspicious signs were found in the checks completed so far. This is not a guarantee that the website is free of malware.';
        if($differences) {
            $details[]='File changes: '.count($differences).'. Updates and intentional edits can also cause file changes.';
            foreach(array_slice($differences,0,20) as $line) $details[]=self::readable_detail($line);
        } elseif(!$first && !$pending && !$problems) $details[]='File changes: No differences from the saved comparison copy were found in the files checked.';
        if($first) $details[]='First check: There is no earlier saved comparison copy, so the plugin cannot tell which files changed before this check.';
        if($problems) {
            $details[]='What the plugin did: Checked the files it could reach, but could not complete the full check. No files were deleted, repaired or quarantined.';
            $details[]='Why it stopped: Some files could not be checked, or the check reached its safety limit. Your developer or host should review the paths and reasons below.';
            foreach(array_slice($result['errors'],0,10) as $error) $details[]=str_replace(array('Total scan safety limit exceeded; coverage incomplete','Directory queue safety limit exceeded; coverage incomplete','size unreadable or exceeds per-file limit','could not hash','unreadable directory','disappeared during scan'),array('Too many files or too much data to finish safely','Too many folders or files to finish safely','Could not read the file size, or this file is too large to check','Could not read this file for comparison','Could not open this folder','The file disappeared while it was being checked'),$error);
        } elseif($pending) $details[]='What the plugin did: Saved its progress and scheduled the next part of the check. No files were deleted or changed. Completion depends on WordPress background tasks running.';
        else $details[]='What the plugin did: Finished the selected file checks and saved the results. No files were deleted, repaired or quarantined.';
        if(!$reviewed) $details[]='Comparison copy: The saved file list has not been verified against trusted originals. This is a setup/review reminder, not a detected threat.';
        $details[]='What you should do: '.($problems?'Ask your developer or host to resolve the incomplete checks, then run the check again.':($pending?'Wait for the check to finish. If it remains unfinished, ask your developer to check WordPress background tasks.':(($findings||$differences)?'Review the listed files with your developer. If you did not authorize the changes, ask your host to investigate.':(!$reviewed?'Have your developer compare the files with trusted originals before approving the saved comparison copy.':'No action is needed for this report. Keep website components updated.'))));
        self::notice($subject,$details,$signature);
    }
    public static function inventory($resume=false) {
        $roots=array('mu-plugins'=>WPMU_PLUGIN_DIR,'plugins'=>WP_PLUGIN_DIR);
        if(defined('WP_CONTENT_DIR')) { $roots['themes']=WP_CONTENT_DIR.'/themes'; $roots['uploads']=WP_CONTENT_DIR.'/uploads'; $roots['cache']=WP_CONTENT_DIR.'/cache'; }
        if(is_dir(ABSPATH)) $roots['root']=rtrim(ABSPATH,'/');
        $state=$resume?get_option('lnkta_guard_scan_state',null):null;
        if(!is_array($state) || !isset($state['pending'],$state['files'],$state['started']) || ($state['version']??'')!==self::VERSION) {
            $state=array('version'=>self::VERSION,'pending'=>array_keys($roots),'files'=>array(),'errors'=>array(),'indicators'=>array(),'entries'=>0,'bytes'=>0,'started'=>time());
        }
        $began=microtime(true); $batch=0; $batch_bytes=0;
        while($state['pending']) {
            if($batch>=5000 || microtime(true)-$began>5 || $batch_bytes>67108864) break;
            if($state['entries']>=250000 || $state['bytes']>2147483648) {
                $state['errors'][]='Total scan safety limit exceeded; coverage incomplete'; $state['pending']=array(); break;
            }
            $rel=array_pop($state['pending']); $parts=explode('/',$rel,2); $label=$parts[0];
            if(!isset($roots[$label]) || (isset($parts[1]) && preg_match('~(?:^|/)\.\.(?:/|$)~',$parts[1]))) { $state['errors'][]='Invalid scan queue path';continue; }
            $path=$roots[$label].(isset($parts[1])?'/'.$parts[1]:'');
            $batch++; $state['entries']++;
            if(preg_match('~(?:^|/)(?:(?:akismet|cache-helper|media-cache|db-helper|maintenance-helper|custom-constants)-33da92c1)(?:[ /\.]|$)~i',$rel)) $state['indicators'][]='Incident-associated path (review provenance): '.$rel;
            if(strpos($rel,'content-sync-connector')!==false || preg_match('~(?:^|/)(?:wp-runtime-guard|wp-site-guard)\.php$~i',$rel)) $state['indicators'][]='Known connector path requires review: '.$rel;
            clearstatcache(true,$path);
            if(is_link($path)) { $state['files'][$rel]='symlink:'.hash('sha256',(string)readlink($path));continue; }
            if(!file_exists($path)) {
                if(!isset($parts[1]) || $label==='root') $state['files'][$rel.'/@directory']='absent';
                else $state['errors'][]=$rel.': disappeared during scan';
                continue;
            }
            if(is_dir($path)) {
                $state['files'][$rel.'/@directory']='present:'.decoct(@fileperms($path)&0777);
                // Root coverage is configuration files only; do not recursively scan WordPress core.
                $children=$label==='root'?array('wp-config.php','.htaccess','.user.ini','php.ini'): @scandir($path);
                if($children===false) { $state['errors'][]=$rel.': unreadable directory';continue; }
                foreach($children as $name) if($name!=='.' && $name!=='..') { if(count($state['pending'])>=250000) { $state['errors'][]='Directory queue safety limit exceeded; coverage incomplete'; break; } $state['pending'][]=$rel.'/'.$name; }
                continue;
            }
            if(!is_file($path)) continue;
            if($label!=='mu-plugins' && !(in_array($label,array('uploads','cache'),true) && preg_match('/\.(?:php[0-9]*|phtml|pht|phar|phps)(?:\.|$)/i',$rel)) && !(strpos($rel,'cache/csc-')===0 && substr($rel,-4)==='.zip') && !preg_match('/\.(?:php[0-9]*|phtml|pht|phar|phps|js|html|htm)$/i',$rel) && !in_array(basename($path),array('.htaccess','.user.ini','php.ini'),true)) continue;
            $size=@filesize($path);
            if($size===false || $size>20971520) { $state['errors'][]=$rel.': size unreadable or exceeds per-file limit';continue; }
            $state['bytes']+=$size; $batch_bytes+=$size; $hash=@hash_file('sha256',$path);
            if($hash===false) $state['errors'][]=$rel.': could not hash';
            else {
                if(in_array($label,array('uploads','cache'),true) && preg_match('/\.(?:php[0-9]*|phtml|pht|phar|phps)(?:\.|$)/i',$rel)) $state['indicators'][]='Executable file in writable directory (review; may be legitimate): '.$rel;
                $state['files'][$rel]=$hash.':mode:'.decoct(@fileperms($path)&0777);
                if($size<=1048576 && preg_match('/\.(?:php[0-9]*|phtml|pht|phar)$/i',$rel)) {
                    $content=@file_get_contents($path);
                    if(is_string($content)) foreach(array('CSC_Watchdog','class WP_Runtime_Guard','WP_RUNTIME_GUARD:BEGIN','csc_recovery_package','csc-inject:') as $marker) if(strpos($content,$marker)!==false && strpos($rel,'plugins/lnkta-security-guard/')!==0) $state['indicators'][]='Connector persistence marker '.$marker.': '.$rel;
                    if(is_string($content) && strpos($content,'chmod(__FILE__,0444)')!==false && strpos($content,'chmod(dirname(__FILE__),0555)')!==false) $state['indicators'][]='Permission-lock pattern from supplied db-helper sample: '.$rel;
                }
            }
        }
        $complete=empty($state['pending']);
        if($resume) {
            if($complete) delete_option('lnkta_guard_scan_state'); else update_option('lnkta_guard_scan_state',$state,false);
        }
        ksort($state['files']);
        return array('files'=>$state['files'],'errors'=>array_values(array_unique($state['errors'])),'indicators'=>array_values(array_unique($state['indicators'])),'entries'=>$state['entries'],'bytes'=>$state['bytes'],'complete'=>$complete,'pending'=>count($state['pending']));
    }
    public static function differences($old,$new) {
        $out=array();
        foreach($new as $p=>$h) if(!array_key_exists($p,$old)) $out[]='ADDED '.$p; elseif($old[$p]!==$h) $out[]='CHANGED '.$p;
        foreach($old as $p=>$h) if(!array_key_exists($p,$new)) $out[]='REMOVED '.$p;
        return $out;
    }
    public static function scan() {
        $lock=get_option('lnkta_guard_scan_lock',0);
        if($lock && time()-(int)$lock<120) return;
        if($lock) delete_option('lnkta_guard_scan_lock');
        if(!add_option('lnkta_guard_scan_lock',time(),'','no')) return;
        try {
            if(class_exists('LNKTA_Guard_Incident')) LNKTA_Guard_Incident::audit();
            $result=self::inventory(true);
            if(!$result['complete']) {
                update_option('lnkta_guard_last_scan',array('time'=>gmdate('c'),'count'=>count($result['files']),'changes'=>array('Scan in progress: '.(int)$result['entries'].' entries examined; '.(int)$result['pending'].' queued. Next batch scheduled.'),'change_count'=>0,'errors'=>$result['errors']),false);
                update_option('lnkta_guard_integrity_alert',true,false);
                self::scan_message($result,array(),get_option('lnkta_guard_file_baseline',null)===null,(bool)get_option('lnkta_guard_baseline_reviewed'));
                if(!wp_next_scheduled('lnkta_guard_integrity_continue')) wp_schedule_single_event(time()+60,'lnkta_guard_integrity_continue');
                return;
            }
            wp_clear_scheduled_hook('lnkta_guard_integrity_continue');
            $old=get_option('lnkta_guard_file_baseline',null);
            update_option('lnkta_guard_reviewable_inventory',array('files'=>$result['files'],'errors'=>$result['errors'],'indicators'=>$result['indicators'],'time'=>time()),false);
            if($old===null && !$result['errors']) { update_option('lnkta_guard_file_baseline',$result['files'],false); }
            $file_changes=$old===null?array():self::differences((array)$old,$result['files']);
            $changes=$old===null?array('Initial observation captured, NOT certified clean. Review against trusted originals.'):self::differences((array)$old,$result['files']);
            $changes=array_merge($changes,$result['indicators']);
            if(!get_option('lnkta_guard_baseline_reviewed')) $changes[]='Baseline has not been reviewed against trusted originals.';
            $report=array('time'=>gmdate('c'),'count'=>count($result['files']),'changes'=>array_slice($changes,0,200),'change_count'=>count($file_changes),'warning_count'=>count($result['indicators']),'errors'=>$result['errors']);
            update_option('lnkta_guard_last_scan',$report,false);
            update_option('lnkta_guard_integrity_alert',!empty($changes)||!empty($result['errors']),false);
            self::scan_message($result,$file_changes,$old===null,(bool)get_option('lnkta_guard_baseline_reviewed'));
        } finally { delete_option('lnkta_guard_scan_lock'); }
    }
    public static function page() {
        if(!current_user_can('manage_options')) return;
        self::setup();
        if(class_exists('LNKTA_Guard_Incident')) LNKTA_Guard_Incident::audit();
        if($_SERVER['REQUEST_METHOD']==='POST') {
            check_admin_referer('lnkta_integrity');
            if(isset($_POST['scan'])) self::scan();
            if(isset($_POST['approve'])) {
                $inventory=get_option('lnkta_guard_reviewable_inventory',array());
                if(isset($inventory['files'],$inventory['time']) && time()-$inventory['time']<DAY_IN_SECONDS && !$inventory['errors'] && !$inventory['indicators']) { update_option('lnkta_guard_file_baseline',$inventory['files'],false); update_option('lnkta_guard_baseline_reviewed',true,false); update_option('lnkta_guard_integrity_alert',false,false); echo '<div class="notice notice-success"><p>Current inventory accepted. This does not certify files as malware-free.</p></div>'; }
                else echo '<div class="notice notice-error"><p>Baseline not accepted: no recent complete scan, incomplete coverage, or incident-associated indicators need review.</p></div>';
            }
        }
        echo '<div class="wrap"><h1>LNKTA Integrity &amp; Hardening</h1><p>Anonymous REST user lookups and author-ID query probes are blocked. Pretty member/author pages and authenticated REST access remain available.</p><p>Dashboard plugin/theme installation and built-in PHP editing are locked. Existing updates remain permitted. New privileged role assignments are blocked unless approved through maintenance mode. Existing privileged accounts must be reviewed separately.</p><p><strong>Maintenance:</strong> set <code>define(\'LNKTA_GUARD_MAINTENANCE\', true);</code> in wp-config.php through trusted hosting access for an intentional installation or privileged role assignment; remove it immediately afterwards. PHP malware and direct database writes can bypass WordPress controls.</p>';
        echo '<p>Hourly integrity cycles use resumable batches and inspect all MU-plugin files plus plugin/theme PHP/JavaScript/HTML, executable files in uploads/cache, selected root configuration files and directory/file permissions, with resource limits. No automatic deletion or restoration. First complete scan captures an unverified observation for change detection; it stays flagged until you review and accept it. Alerts go to <strong>'.esc_html(get_option('lnkta_guard_alert_email')).'</strong>. Monitor mail delivery separately.</p>';
        echo '<form method="post">'; wp_nonce_field('lnkta_integrity');
        submit_button('Run integrity scan','secondary','scan',false);
        echo ' '; submit_button('Accept last completed inventory as reviewed baseline','secondary','approve',false); echo '</form>';
        $r=get_option('lnkta_guard_last_scan',array());
        if($r) { echo '<h2>Last scan</h2><p>'.esc_html($r['time']).' — '.esc_html((string)$r['count']).' file/directory records; '.esc_html((string)$r['change_count']).' differences.</p><pre style="white-space:pre-wrap">'.esc_html(implode("\n",array_merge($r['changes'],$r['errors']))).'</pre>'; }
        echo '<h2>Email alerts</h2><p>Emails are sent only for suspicious file findings, executable files or changes to website code/security settings, and evidence of the known unwanted connector. Routine cache/media changes, background-task changes, scan progress and setup reminders stay in this dashboard. Unchanged findings are not emailed again each day. A successful complete check without findings allows a later recurrence to alert again.</p><h2>WordPress persistence checks</h2><p>Known connector REST commands, activation entries and scheduled hooks are blocked. WordPress cron hook/argument changes and connector options are monitored. This cannot stop OS/cPanel cron or existing malicious PHP. First cron inventory is unverified.</p>';
        $incident=get_option('lnkta_guard_incident_findings',array());
        if($incident) echo '<pre>'.esc_html(implode("\n",$incident)).'</pre>';
        echo '<h2>Remaining server work</h2><p>Protect code/MU directories with host-controlled ownership and read-only permissions; keep PHP runtime unable to change that ownership. Block PHP execution in uploads. Configure external integrity monitoring, WAF and administrator 2FA. Compare core, premium and custom code with trusted originals, and rotate compromised credentials.</p><p>Coverage excludes core files outside the listed root configuration, server cron and symlink targets; PHP marker inspection is limited to files up to 1 MiB. All scans have resource limits. Files created and removed between scans may escape detection. A compromised PHP process can alter this plugin, its database baseline, scheduled jobs and mail. Use external monitoring for trustworthy alerts.</p></div>';
    }
}
LNKTA_Guard_Hardening::boot();
