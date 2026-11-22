<?php
error_reporting(E_ALL);
define('ABSPATH', __DIR__.'/'); define('DAY_IN_SECONDS',86400);
define('WPMU_PLUGIN_DIR', __DIR__.'/fixture/mu-plugins'); define('WP_PLUGIN_DIR',__DIR__.'/fixture/plugins');
@mkdir(WPMU_PLUGIN_DIR,0777,true); @mkdir(WP_PLUGIN_DIR,0777,true);
$GLOBALS['opts']=array('lnkta_guard_privileged_baseline'=>array('1'=>array('administrator'))); $GLOBALS['opts']['lnkta_guard_alert_email']='admin@example.invalid'; $GLOBALS['logged']=false; $GLOBALS['mails']=array(); $GLOBALS['transients']=array();
function add_filter(...$a){} function add_action(...$a){} function register_activation_hook(...$a){} function register_deactivation_hook(...$a){}
function is_user_logged_in(){return $GLOBALS['logged'];} function current_user_can(...$a){return true;}
function get_option($k,$d=false){return $GLOBALS['opts'][$k]??$d;} function update_option($k,$v,...$a){$GLOBALS['opts'][$k]=$v;return true;}
function delete_option($k){unset($GLOBALS['opts'][$k]);} function add_option($k,$v,...$a){if(isset($GLOBALS['opts'][$k]))return false;$GLOBALS['opts'][$k]=$v;return true;}
function sanitize_email($s){return filter_var($s,FILTER_SANITIZE_EMAIL);} function sanitize_key($s){return preg_replace('/[^a-z0-9_-]/','',strtolower($s));} function sanitize_text_field($s){return strip_tags((string)$s);}
function get_current_user_id(){return 1;} function get_transient($k){return $GLOBALS['transients'][$k]??false;} function set_transient($k,$v,$ttl){$GLOBALS['transients'][$k]=$v;}
function is_email($e){return filter_var($e,FILTER_VALIDATE_EMAIL);} function wp_mail(...$args){$GLOBALS['mails'][]=$args;return empty($GLOBALS['mail_fail']);} function home_url($s){return 'https://example.invalid'.$s;}
function wp_date($format){return $GLOBALS['email_test_day']??'2026-11-18';}
class EmailQuotaDatabase {
    public $prefix='wp_'; public $buckets=array(); public $fail=false;
    function prepare($sql,...$args){return array($sql,$args);}
    function query($prepared){
        if($this->fail)return false;
        list($sql,$args)=$prepared; $bucket=$args[0];
        if(strpos($sql,'INSERT IGNORE')===0){if(isset($this->buckets[$bucket]))return 0;$this->buckets[$bucket]=0;return 1;}
        if(strpos($sql,'UPDATE ')===0 && isset($this->buckets[$bucket]) && $this->buckets[$bucket]<$args[1]){$this->buckets[$bucket]++;return 1;}
        return 0;
    }
}
$GLOBALS['wpdb']=new EmailQuotaDatabase();
// Existing notification tests exercise deduplication independently of the cap.
$GLOBALS['opts']['lnkta_guard_email_daily_limit']=100;
function get_role($r){return (object)array('capabilities'=>array('manage_options'=>$r==='administrator'));}
class FakeUser {public $user_login='fixture-user';public $roles=array('administrator');function remove_role($r){$this->roles=array_values(array_diff($this->roles,array($r)));}function set_role($r){$this->roles=array($r);}}
$GLOBALS['users']=array(1=>new FakeUser(),99=>new FakeUser());function get_userdata($id){return $GLOBALS['users'][$id]??false;}
class WP_Error {public $code;public $data;function __construct($c,$m,$d=null){$this->code=$c;$this->data=$d;}function get_error_code(){return $this->code;}}
class WP_Session_Tokens {static function get_instance($id){return new self;}function destroy_all(){}}
function wp_clear_scheduled_hook($a){} function wp_next_scheduled($a){return $GLOBALS['scheduled'][$a]??false;} function wp_schedule_event($time,$period,$hook){$GLOBALS['scheduled'][$hook]=$time;$GLOBALS['schedule_calls']=($GLOBALS['schedule_calls']??0)+1;return true;} function wp_schedule_single_event(...$a){} function nocache_headers(){} function status_header($s){$GLOBALS['status']=$s;} function wp_die($m,$t,$a){throw new Exception('blocked:'.$a['response']);}
require __DIR__.'/../lnkta-security-guard/lnkta-security-guard.php';
function check($condition,$name){if(!$condition)throw new Exception('FAIL '.$name);echo 'PASS '.$name."\n";}
foreach(array('/wp/v2/users','/wp/v2/users/1','/wp/v2/users/me','wp/v2/users/1','/wp/v2/%75sers/1') as $r)check(LNKTA_Guard_Hardening::user_route($r),'user route '.$r);
check(!LNKTA_Guard_Hardening::user_route('/wp/v2/usersettings'),'prefix false-positive avoided');
$request=new class {function get_route(){return '/wp/v2/users/1';}};
check(LNKTA_Guard_Hardening::rest(null,null,$request) instanceof WP_Error,'anonymous user REST blocked');
$GLOBALS['logged']=true;check(LNKTA_Guard_Hardening::rest(null,null,$request)===null,'authenticated REST preserved');$GLOBALS['logged']=false;
check(!isset(LNKTA_Guard_Hardening::endpoints(array('/wp/v2/users'=>1,'/wp/v2/posts'=>2))['/wp/v2/users']),'anonymous user discovery removed');
check(LNKTA_Guard_Hardening::caps(array('install_plugins'),'install_plugins',1,array())===array('do_not_allow'),'plugin installer locked');
check(LNKTA_Guard_Hardening::caps(array('update_plugins'),'update_plugins',1,array())===array('update_plugins'),'existing updates preserved');
$_GET=array('author'=>1);try{LNKTA_Guard_Hardening::author_probe();check(false,'author query');}catch(Exception $e){check($e->getMessage()==='blocked:404','author-ID probe blocked');}
$_GET=array('author_name'=>'public-member');LNKTA_Guard_Hardening::author_probe();check(true,'author-name archives preserved');
LNKTA_Guard_Hardening::guard_role(99,'administrator');check($GLOBALS['users'][99]->roles===array('subscriber'),'unapproved administrator demoted');
LNKTA_Guard_Hardening::guard_role(1,'administrator');check($GLOBALS['users'][1]->roles===array('administrator'),'existing approved administrator preserved');
foreach(array('test.php','test.PHTML','test.php.jpg','.user.ini') as $f)check(isset(LNKTA_Security_Guard::upload(array('name'=>$f))['error']),'blocked upload '.$f);
foreach(array('photo.jpg','photo.webp','document.pdf','icon.svg') as $f)check(!isset(LNKTA_Security_Guard::upload(array('name'=>$f))['error']),'normal upload eligible '.$f);
file_put_contents(WPMU_PLUGIN_DIR.'/loader.php','original');file_put_contents(WP_PLUGIN_DIR.'/main.php','original');
LNKTA_Guard_Hardening::scan();check(is_array(get_option('lnkta_guard_file_baseline')),'initial unverified observation captured');
file_put_contents(WPMU_PLUGIN_DIR.'/loader.php','changed');unlink(WP_PLUGIN_DIR.'/main.php');file_put_contents(WP_PLUGIN_DIR.'/inert-added.php','inert text');
LNKTA_Guard_Hardening::scan();$changes=implode("\n",get_option('lnkta_guard_last_scan')['changes']);
check(strpos($changes,'CHANGED mu-plugins/loader.php')!==false,'MU modification detected');check(strpos($changes,'ADDED plugins/inert-added.php')!==false,'added plugin PHP detected');check(strpos($changes,'REMOVED plugins/main.php')!==false,'removed plugin PHP detected');
check(get_option('lnkta_guard_integrity_alert')===true,'dashboard alert set');check(!empty($GLOBALS['opts']['lnkta_guard_events']),'events recorded');
check(count($GLOBALS['mails'])>=1,'email alerts dispatched through mail stub');
mkdir(WP_PLUGIN_DIR.'/cache-helper-33da92c1');file_put_contents(WP_PLUGIN_DIR.'/cache-helper-33da92c1/cache-helper-33da92c1.php','');
file_put_contents(WPMU_PLUGIN_DIR.'/permission-fixture.php','<?php /* Test fixture, never executed. */ chmod(__FILE__,0444); chmod(dirname(__FILE__),0555);');
$inventory=LNKTA_Guard_Hardening::inventory();check(count($inventory['indicators'])>=2,'incident paths and permission-lock signature flagged without execution');
chmod(WPMU_PLUGIN_DIR.'/loader.php',0444);clearstatcache();$changed=LNKTA_Guard_Hardening::inventory();check($changed['files']['mu-plugins/loader.php']!==$inventory['files']['mu-plugins/loader.php'],'permission-only modification detected');
$old=array('a'=>'1','b'=>'2');check(count(LNKTA_Guard_Hardening::differences($old,array('a'=>'3','c'=>'4')))===3,'diff all change types');
echo "All functional tests passed; WordPress APIs were stubbed, filesystem scan was real.\n";

@mkdir(WP_PLUGIN_DIR.'/bulk');for($i=0;$i<5005;$i++)file_put_contents(WP_PLUGIN_DIR.'/bulk/'.$i.'.txt','');
$r=LNKTA_Guard_Hardening::inventory(true);check(!$r['complete'],'large inventory pauses into a persisted batch');
$r=LNKTA_Guard_Hardening::inventory(true);check($r['complete'],'next batch resumes and completes');
check(get_option('lnkta_guard_scan_state',null)===null,'completed batch queue cleaned up');

$blocked=new class {function get_route(){return '/csc/v1/command';}};
check(LNKTA_Guard_Incident::rest(null,null,$blocked) instanceof WP_Error,'connector signed REST blocked');
$normal=new class {function get_route(){return '/wp/v2/posts';}};
check(LNKTA_Guard_Incident::rest(null,null,$normal)===null,'normal REST unchanged');
check(LNKTA_Guard_Incident::plugins(array('safe/main.php',LNKTA_Guard_Incident::CONNECTOR))===array('safe/main.php'),'connector activation filtered');
check(LNKTA_Guard_Incident::schedule(null,(object)array('hook'=>'csc_guardian_healthcheck'))===false,'connector cron creation blocked');
check(LNKTA_Guard_Incident::schedule(null,(object)array('hook'=>'normal_hook'))===null,'normal cron scheduling unchanged');
$a=array(100=>array('normal'=>array('key'=>array('schedule'=>'hourly','interval'=>3600,'args'=>array('secret')))));
$b=array(200=>$a[100]);check(LNKTA_Guard_Incident::cron_inventory($a)===LNKTA_Guard_Incident::cron_inventory($b),'cron normal reschedule produces no change');
$GLOBALS['opts']['cron']=$a;LNKTA_Guard_Incident::audit();$mailcount=count($GLOBALS['mails']);
$GLOBALS['opts']['cron']=$b;LNKTA_Guard_Incident::audit();check(count($GLOBALS['mails'])===$mailcount,'no cron alert for ordinary rescheduling');
$GLOBALS['opts']['cron'][300]=array('unexpected'=>array('key'=>array('schedule'=>false,'args'=>array('sensitive-token'))));
LNKTA_Guard_Incident::audit();check(count($GLOBALS['mails'])===$mailcount,'ordinary WordPress cron changes stay out of email');
check(strpos(serialize(end($GLOBALS['mails'])),'sensitive-token')===false,'cron arguments never emailed');
$GLOBALS['opts']['csc_identity']=array('site_key'=>'secret');LNKTA_Guard_Incident::audit();check(in_array('Connector database option present: csc_identity',get_option('lnkta_guard_incident_findings')),'connector database persistence detected');
define('WP_CONTENT_DIR',__DIR__.'/fixture');
@mkdir(WP_CONTENT_DIR.'/themes');@mkdir(WP_CONTENT_DIR.'/themes/test');@mkdir(WP_CONTENT_DIR.'/uploads');@mkdir(WP_CONTENT_DIR.'/cache');
file_put_contents(WP_CONTENT_DIR.'/themes/test/functions.php','<?php /* WP_RUNTIME_GUARD:BEGIN */');
file_put_contents(WP_CONTENT_DIR.'/uploads/inert.php.jpg','inert fixture');
$r=LNKTA_Guard_Hardening::inventory();if(!$r['complete']){delete_option('lnkta_guard_scan_state');do{$r=LNKTA_Guard_Hardening::inventory(true);}while(!$r['complete']);}
check(isset($r['files']['themes/test/functions.php']),'theme functions inventoried');
check(isset($r['files']['uploads/inert.php.jpg']),'double extension executable inventoried');
check(strpos(implode('|',$r['indicators']),'WP_RUNTIME_GUARD:BEGIN')!==false,'theme persistence marker detected');
echo "Incident containment tests passed.\n";

$GLOBALS['transients']=array();$GLOBALS['mails']=array();delete_option('lnkta_guard_last_email_file_scan');
$sample=array('files'=>array('plugins/test.php'=>'x'),'errors'=>array('Total scan safety limit exceeded; coverage incomplete'),'indicators'=>array(),'complete'=>true);
LNKTA_Guard_Hardening::scan_message($sample,array(),true,false);
check(count($GLOBALS['mails'])===0,'incomplete scan and baseline reminders do not email');
$sample['errors']=array();$sample['complete']=false;LNKTA_Guard_Hardening::scan_message($sample,array(),true,false);
check(count($GLOBALS['mails'])===0,'scan progress does not email');
$sample['complete']=true;LNKTA_Guard_Hardening::scan_message($sample,array('ADDED cache/breeze/a.html','CHANGED cache/breeze/a.js','ADDED uploads/photo.jpg','CHANGED cache/breeze/@directory'),false,true);
check(count($GLOBALS['mails'])===0,'Breeze cache and normal media churn do not email');
LNKTA_Guard_Hardening::scan_message($sample,array('CHANGED themes/test/functions.php'),false,true);
check(count($GLOBALS['mails'])===1,'theme code change emails');
$mail=end($GLOBALS['mails']);check(strpos($mail[2],'themes/test/functions.php')!==false,'security email identifies affected file');
LNKTA_Guard_Hardening::scan_message($sample,array('CHANGED themes/test/functions.php'),false,true);
check(count($GLOBALS['mails'])===1,'same unresolved change not emailed every day');
$sample['files']['themes/test/functions.php']='new-hash';LNKTA_Guard_Hardening::scan_message($sample,array('CHANGED themes/test/functions.php'),false,true);
check(count($GLOBALS['mails'])===2,'further change to affected file emails again');
$sample['files']['cache/breeze/ordinary.html']='churn';LNKTA_Guard_Hardening::scan_message($sample,array('CHANGED themes/test/functions.php'),false,true);
check(count($GLOBALS['mails'])===2,'unrelated cache churn cannot retrigger unchanged code alert');
LNKTA_Guard_Hardening::scan_message($sample,array(),false,true);check(count($GLOBALS['mails'])===2,'clean completed scan does not email');
LNKTA_Guard_Hardening::scan_message($sample,array('CHANGED themes/test/functions.php'),false,true);check(count($GLOBALS['mails'])===3,'recurrence after clean complete scan emails again');
$sample['indicators']=array('Known connector path requires review: plugins/content-sync-connector/main.php');
$sample['errors']=array('unreadable directory');LNKTA_Guard_Hardening::scan_message($sample,array(),false,true);
check(count($GLOBALS['mails'])===4,'suspicious finding still emails when other coverage incomplete');
$mail=end($GLOBALS['mails']);check(strpos($mail[1],'Suspicious files')!==false,'threat stays prominent in subject');
check(count(LNKTA_Guard_Hardening::email_changes(array('ADDED cache/breeze/payload.php','ADDED uploads/bad.php.jpg','CHANGED plugins/breeze/breeze.php','CHANGED root/wp-config.php')) )===4,'executable and security-sensitive changes never broadly ignored');
$before=count($GLOBALS['mails']);LNKTA_Guard_Hardening::notice('User account created',array('User ID: 42'));
check(count($GLOBALS['mails'])===$before+1,'new account event emails');$before=count($GLOBALS['mails']);
delete_option('csc_identity');$GLOBALS['opts']['cron']=array(100=>array('od_trigger_page_cache_invalidation'=>array('x'=>array('schedule'=>false,'args'=>array()))));
LNKTA_Guard_Incident::audit();check(count($GLOBALS['mails'])===$before,'cache invalidation background task does not email');
echo "Threat-only notification tests passed.\n";

delete_option('lnkta_guard_email_daily_limit');
$GLOBALS['wpdb']=new EmailQuotaDatabase(); $GLOBALS['mails']=array();
check(LNKTA_Guard_Hardening::email_limit()===2,'upgrades and fresh installs default to two emails');
LNKTA_Guard_Hardening::notice('Suspicious files need review',array('limit test A'));
LNKTA_Guard_Hardening::notice('Suspicious files need review',array('limit test A'));
LNKTA_Guard_Hardening::notice('Blocked connector activation entry',array('limit test B'));
for($i=0;$i<96;$i++)LNKTA_Guard_Hardening::notice('Website files have changed',array('changing finding '.$i));
check(count($GLOBALS['mails'])===2,'all subjects share default cap despite 96 changing findings');
check($GLOBALS['wpdb']->buckets[LNKTA_Guard_Hardening::email_bucket()]===2,'duplicate findings do not consume quota');
check(!empty(get_option('lnkta_guard_events')),'findings still recorded after limit reached');
check(get_option('lnkta_guard_last_email_'.hash('sha256','Website files have changed'))!==hash('sha256','Website files have changedchanging finding 95'),'suppressed finding is not marked as sent');
update_option('lnkta_guard_email_daily_limit',3);
LNKTA_Guard_Hardening::notice('Website files have changed',array('changing finding 95'));
check(count($GLOBALS['mails'])===3,'custom limit permits only additional capacity without resetting count');
update_option('lnkta_guard_email_daily_limit',1);
LNKTA_Guard_Hardening::notice('Website files have changed',array('after reduction'));
check(count($GLOBALS['mails'])===3,'lowering the setting cannot reset used quota');
$GLOBALS['email_test_day']='2026-11-19'; delete_option('lnkta_guard_email_daily_limit');
LNKTA_Guard_Hardening::notice('Website files have changed',array('next day first'));
LNKTA_Guard_Hardening::notice('Website files have changed',array('next day second'));
LNKTA_Guard_Hardening::notice('Website files have changed',array('next day third'));
check(count($GLOBALS['mails'])===5,'site calendar day rollover resets shared allowance');
update_option('lnkta_guard_email_daily_limit',0); $GLOBALS['email_test_day']='2026-11-20';
LNKTA_Guard_Hardening::notice('Website files have changed',array('muted'));
check(count($GLOBALS['mails'])===5,'zero disables emails');
delete_option('lnkta_guard_email_daily_limit'); $GLOBALS['mail_fail']=true;
for($i=0;$i<10;$i++)LNKTA_Guard_Hardening::notice('Website files have changed',array('failed delivery '.$i));
check(count($GLOBALS['mails'])===7,'failed delivery attempts cannot cause unlimited retries');
$GLOBALS['mail_fail']=false; $GLOBALS['email_test_day']='2026-11-21'; $GLOBALS['wpdb']->fail=true;
LNKTA_Guard_Hardening::notice('Website files have changed',array('database unavailable'));
check(count($GLOBALS['mails'])===7,'database failure never bypasses cap');
update_option('lnkta_guard_email_daily_limit','invalid');
check(LNKTA_Guard_Hardening::email_limit()===2,'invalid stored limit uses safe default');
echo "Daily email limit tests passed.\n";

function is_admin(){return !empty($GLOBALS['header_admin']);}
function is_ssl(){return !empty($GLOBALS['header_https']);}
$o=LNKTA_Guard_Headers::defaults();
$h=LNKTA_Guard_Headers::build($o,false,true);
check(($h['X-Content-Type-Options']??'')==='nosniff','default MIME protection header');
check(($h['Referrer-Policy']??'')==='strict-origin-when-cross-origin','default referrer protection');
check(!isset($h['Strict-Transport-Security']),'HSTS requires explicit opt in');
check(!isset($h['Content-Security-Policy'])&&!isset($h['X-Frame-Options']),'potentially disruptive restrictions opt in');
$o['hsts']=true;$o['hsts_subdomains']=true;
check(!isset(LNKTA_Guard_Headers::build($o,false)['Strict-Transport-Security']),'HSTS never sent over HTTP');
check(LNKTA_Guard_Headers::build($o,true)['Strict-Transport-Security']==='max-age=86400; includeSubDomains','HTTPS HSTS short initial lifetime');
$o['hsts_age']=0;check(LNKTA_Guard_Headers::build($o,true)['Strict-Transport-Security']==='max-age=0; includeSubDomains','explicit HSTS reset supported');
$o['hsts_age']=123;check(LNKTA_Guard_Headers::sanitize($o)['hsts_age']===86400,'HSTS durations constrained');
$o['frame']=true;$o['permissions']=true;$o['csp_mode']='report';
$h=LNKTA_Guard_Headers::build($o,true,true);check(isset($h['Content-Security-Policy-Report-Only'])&&!isset($h['Content-Security-Policy']),'CSP testing does not enforce');
check(isset($h['Permissions-Policy'])&&$h['X-Frame-Options']==='SAMEORIGIN','optional permissions and framing enabled');
$o['csp_mode']='enforce';$h=LNKTA_Guard_Headers::build($o,true,true);check(isset($h['Content-Security-Policy'])&&!isset($h['Content-Security-Policy-Report-Only']),'CSP enforce mode exclusive');
$h=LNKTA_Guard_Headers::build($o,true,false);check(!isset($h['Content-Security-Policy'])&&!isset($h['Permissions-Policy']),'frontend-only policies absent in other contexts');
check(!LNKTA_Guard_Headers::safe_value("default-src 'self'\r\nX-Evil: yes"),'CRLF injection rejected');
check(!LNKTA_Guard_Headers::safe_value(str_repeat('a',8193)),'oversized policies rejected');
$o['csp_value']="bad\nheader";check(strpos(LNKTA_Guard_Headers::build($o,true,true)['Content-Security-Policy'],"\n")===false,'invalid saved policy cannot emit header injection');
$merged=LNKTA_Guard_Headers::merge(array('content-security-policy'=>"default-src 'none'"),array('Content-Security-Policy'=>"default-src 'self'"));check(count($merged)===1&&$merged['content-security-policy']==="default-src 'none'",'existing policy preserved case insensitively');
$GLOBALS['opts']['lnkta_guard_headers']=$o;$GLOBALS['header_https']=true;$GLOBALS['header_admin']=true;
check(!isset(LNKTA_Guard_Headers::filter_headers(array())['Content-Security-Policy']),'admin avoids frontend CSP');
$GLOBALS['header_admin']=false;$GLOBALS['pagenow']='wp-login.php';check(!isset(LNKTA_Guard_Headers::filter_headers(array())['Content-Security-Policy']),'login avoids frontend CSP');
$GLOBALS['pagenow']='index.php';check(isset(LNKTA_Guard_Headers::filter_headers(array())['Content-Security-Policy']),'frontend receives configured CSP');
define('REST_REQUEST',true);check(!isset(LNKTA_Guard_Headers::filter_headers(array())['Content-Security-Policy']),'REST avoids frontend CSP');
$o['enabled']=false;check(LNKTA_Guard_Headers::build($o,true,true)===array(),'master switch stops module headers');
$o['enabled']=true;define('LNKTA_GUARD_DISABLE_HEADERS',true);check(LNKTA_Guard_Headers::build($o,true,true)===array(),'hosting emergency switch stops module headers');
echo "Header tests passed.\n";


foreach(array('',"<?php\n// Silence is golden.\n","<?php /* No output. */ ?>\n") as $body)check(LNKTA_Guard_Hardening::harmless_index('uploads/crocoblocks/index.php',$body),'empty/comment-only index recognized');
foreach(array('<?php echo "changed";','<?php require "another-file.php";','<?php // Silence is golden.' . "\n" . 'echo "changed";','<?php ?> <script>test</script>') as $body)check(!LNKTA_Guard_Hardening::harmless_index('uploads/crocoblocks/index.php',$body),'executable or output-producing index never exempt');
check(!LNKTA_Guard_Hardening::harmless_index('uploads/crocoblocks/payload.php','<?php // empty'),'exception restricted to index.php');
check(!LNKTA_Guard_Hardening::permission_lock_pattern('<?php $example="chmod(__FILE__,0444) and chmod(dirname(__FILE__),0555)";'),'quoted permission signature is not executable behavior');
check(!LNKTA_Guard_Hardening::permission_lock_pattern('<?php /* chmod(__FILE__,0444); chmod(dirname(__FILE__),0555); */'),'commented permission signature is not executable behavior');
check(LNKTA_Guard_Hardening::permission_lock_pattern('<?php @chmod ( __FILE__ , 0444 ); @chmod( dirname(__FILE__), 0555 );'),'actual paired permission calls remain detected');
check(!LNKTA_Guard_Hardening::permission_lock_pattern(file_get_contents(__DIR__.'/../lnkta-security-guard/hardening.php')),'scanner does not flag its own detection rules');
@mkdir(WP_CONTENT_DIR.'/uploads/crocoblocks');file_put_contents(WP_CONTENT_DIR.'/uploads/crocoblocks/index.php',"<?php\n// Silence is golden.\n");
@mkdir(WP_PLUGIN_DIR.'/lnkta-security-guard');copy(__DIR__.'/../lnkta-security-guard/hardening.php',WP_PLUGIN_DIR.'/lnkta-security-guard/hardening.php');
delete_option('lnkta_guard_scan_state');do{$r=LNKTA_Guard_Hardening::inventory(true);}while(!$r['complete']);
check(isset($r['files']['uploads/crocoblocks/index.php']),'harmless index still inventoried and hashed');
check(isset($r['safe_indexes']['uploads/crocoblocks/index.php']),'content-proven harmless index recorded');
check(strpos(implode('|',$r['indicators']),'uploads/crocoblocks/index.php')===false,'comment-only index produces no malware/location warning');
check(strpos(implode('|',$r['indicators']),'plugins/lnkta-security-guard/hardening.php')===false,'guard detection source produces no self-warning');
check(LNKTA_Guard_Hardening::email_changes(array('ADDED uploads/crocoblocks/index.php'),$r['safe_indexes'])===array(),'harmless index addition does not email');
check(count(LNKTA_Guard_Hardening::email_changes(array('CHANGED plugins/lnkta-security-guard/hardening.php'),$r['safe_indexes']))===1,'guard code modifications still reported');
file_put_contents(WP_CONTENT_DIR.'/uploads/crocoblocks/index.php','<?php echo "changed";');
delete_option('lnkta_guard_scan_state');do{$r=LNKTA_Guard_Hardening::inventory(true);}while(!$r['complete']);
check(!isset($r['safe_indexes']['uploads/crocoblocks/index.php']),'exemption removed when content becomes executable');
check(strpos(implode('|',$r['indicators']),'uploads/crocoblocks/index.php')!==false,'executable index generates warning');
check(count(LNKTA_Guard_Hardening::email_changes(array('CHANGED uploads/crocoblocks/index.php'),$r['safe_indexes']))===1,'executable change eligible for email');
echo "False-positive regression tests passed.\n";

// Account events remain visible when hook-based or database-based observations fire.
$GLOBALS['wpdb']=new EmailQuotaDatabase();$GLOBALS['email_test_day']='2026-11-23';update_option('lnkta_guard_email_daily_limit',100);
$before=count($GLOBALS['mails']);
LNKTA_Guard_Hardening::account_created(99);
check(count($GLOBALS['mails'])===$before+1,'registration hook sends an account alert');
check(strpos(end($GLOBALS['mails'])[2],'User ID: 99')!==false,'account alert identifies affected account');
$before=count($GLOBALS['mails']);
LNKTA_Guard_Hardening::notice('Blocked privileged role assignment',array('User ID: 123','Role: administrator'));
check(count($GLOBALS['mails'])===$before+1,'blocked privilege event is email eligible');
class AccountDatabase extends EmailQuotaDatabase {
    public $users='wp_users';public $usermeta='wp_usermeta';public $last_error='';public $rows=array();
    function get_results($query,$format){return $this->rows;}
}
if(!defined('ARRAY_A'))define('ARRAY_A','ARRAY_A');
$db=new AccountDatabase();$GLOBALS['wpdb']=$db;delete_option('lnkta_guard_accounts_observed');
$db->rows=array(array('ID'=>1,'user_login'=>'trusted-existing','meta_value'=>'existing-permissions'));
$before=count($GLOBALS['mails']);LNKTA_Guard_Hardening::audit_accounts();
check(count($GLOBALS['mails'])===$before,'initial account observation does not accuse existing users');
$db->rows[]=array('ID'=>124,'user_login'=>'unexpected','meta_value'=>'new-permissions');LNKTA_Guard_Hardening::audit_accounts();
check(count($GLOBALS['mails'])===$before+1,'persistent direct-database account creation detected');
LNKTA_Guard_Hardening::audit_accounts();check(count($GLOBALS['mails'])===$before+1,'unchanged account inventory does not repeat alerts');
$db->rows[1]['meta_value']='changed-permissions';LNKTA_Guard_Hardening::audit_accounts();
check(count($GLOBALS['mails'])===$before+2,'persisted permission change detected without role hook');
array_pop($db->rows);LNKTA_Guard_Hardening::audit_accounts();check(count($GLOBALS['mails'])===$before+3,'account removal detected');
$saved=get_option('lnkta_guard_accounts_observed');$db->last_error='test failure';LNKTA_Guard_Hardening::audit_accounts();
check(get_option('lnkta_guard_accounts_observed')===$saved,'database error cannot replace account observation');$db->last_error='';
$db->rows=array_fill(0,5001,array('ID'=>1,'user_login'=>'test','meta_value'=>''));LNKTA_Guard_Hardening::audit_accounts();
check(get_option('lnkta_guard_accounts_observed')===$saved,'incomplete account coverage keeps previous observation');
update_option('lnkta_guard_email_daily_limit',0);$before=count($GLOBALS['mails']);
LNKTA_Guard_Hardening::notice('User account created',array('User ID: 125'));
check(count($GLOBALS['mails'])===$before,'account events respect email disable/cap');
check(strpos(get_option('lnkta_guard_account_reports')[0]['email'],'not confirmed')!==false,'suppressed account alert retained with honest delivery status');
echo "Account alert and inventory tests passed.\n";

$db->rows=array(array('ID'=>1,'user_login'=>'trusted-existing','meta_value'=>'existing-permissions'));
$roles=get_option('lnkta_guard_privileged_baseline');delete_option('lnkta_guard_monitoring_version');$GLOBALS['scheduled']=array();$GLOBALS['schedule_calls']=0;
LNKTA_Guard_Hardening::ensure_monitoring();
check(!empty($GLOBALS['scheduled']['lnkta_guard_integrity']),'monitoring starts without an admin settings visit');
check(get_option('lnkta_guard_monitoring_version')===LNKTA_Guard_Hardening::VERSION,'startup migration version recorded');
LNKTA_Guard_Hardening::ensure_monitoring();check($GLOBALS['schedule_calls']===1,'normal requests do not duplicate scan scheduling');
unset($GLOBALS['scheduled']['lnkta_guard_integrity']);LNKTA_Guard_Hardening::ensure_monitoring();check($GLOBALS['schedule_calls']===2,'missing schedule restored after reactivation');
check(get_option('lnkta_guard_privileged_baseline')===$roles,'automatic monitoring never approves privileged accounts');
echo "Monitoring startup tests passed.\n";
