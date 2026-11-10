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
function sanitize_key($s){return preg_replace('/[^a-z0-9_-]/','',strtolower($s));} function sanitize_text_field($s){return strip_tags((string)$s);}
function get_current_user_id(){return 1;} function get_transient($k){return $GLOBALS['transients'][$k]??false;} function set_transient($k,$v,$ttl){$GLOBALS['transients'][$k]=$v;}
function is_email($e){return filter_var($e,FILTER_VALIDATE_EMAIL);} function wp_mail(...$args){$GLOBALS['mails'][]=$args;return true;} function home_url($s){return 'https://example.invalid'.$s;}
function get_role($r){return (object)array('capabilities'=>array('manage_options'=>$r==='administrator'));}
class FakeUser {public $roles=array('administrator');function remove_role($r){$this->roles=array_values(array_diff($this->roles,array($r)));}function set_role($r){$this->roles=array($r);}}
$GLOBALS['users']=array(1=>new FakeUser(),99=>new FakeUser());function get_userdata($id){return $GLOBALS['users'][$id]??false;}
class WP_Error {public $code;public $data;function __construct($c,$m,$d=null){$this->code=$c;$this->data=$d;}function get_error_code(){return $this->code;}}
class WP_Session_Tokens {static function get_instance($id){return new self;}function destroy_all(){}}
function wp_clear_scheduled_hook($a){} function wp_next_scheduled($a){return false;} function wp_schedule_single_event(...$a){} function nocache_headers(){} function status_header($s){$GLOBALS['status']=$s;} function wp_die($m,$t,$a){throw new Exception('blocked:'.$a['response']);}
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
file_put_contents(WPMU_PLUGIN_DIR.'/permission-fixture.php','inert marker chmod(__FILE__,0444) and chmod(dirname(__FILE__),0555)');
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
check(count($GLOBALS['mails'])===$before,'routine account event stays in dashboard');
delete_option('csc_identity');$GLOBALS['opts']['cron']=array(100=>array('od_trigger_page_cache_invalidation'=>array('x'=>array('schedule'=>false,'args'=>array()))));
LNKTA_Guard_Incident::audit();check(count($GLOBALS['mails'])===$before,'cache invalidation background task does not email');
echo "Threat-only notification tests passed.\n";

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
