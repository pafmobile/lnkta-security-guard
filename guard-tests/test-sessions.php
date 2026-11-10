<?php
error_reporting(E_ALL);
define('ABSPATH',__DIR__.'/session-fixture/');
function add_action(...$a){} function add_filter(...$a){}
class Stop extends Exception{}
$GLOBALS['admin']=true;$GLOBALS['multi']=false;$GLOBALS['nonce']=true;$GLOBALS['pw']=true;
function current_user_can($a){return $GLOBALS['admin'];}function is_multisite(){return $GLOBALS['multi'];}
function check_admin_referer($a){if(!$GLOBALS['nonce'])throw new Stop('nonce');}
function wp_die($m,...$a){throw new Stop($m);}function wp_get_current_user(){return (object)array('ID'=>1,'user_pass'=>'hash');}
function wp_check_password(...$a){return $GLOBALS['pw'];}function wp_unslash($v){return $v;}
require __DIR__.'/../lnkta-security-guard/sessions.php';
function check($ok,$message){if(!$ok)throw new Exception('FAIL '.$message);echo 'PASS '.$message."\n";}
function denied($call,$name){try{$call();throw new Exception('FAIL '.$name);}catch(Stop $e){echo 'PASS '.$name."\n";}}
function refused($call,$name){try{$call();throw new Exception('FAIL '.$name);}catch(RuntimeException $e){echo 'PASS '.$name."\n";}}
$source="<?php\n// Preserve this comment and database configuration.\ndefine('DB_PASSWORD', 'fixture-only');\n";
foreach(LNKTA_Guard_Sessions::keys() as $key)$source.="define( '$key', 'old-$key' );\n";
$source.="require_once ABSPATH . 'wp-settings.php';\n";
$r=LNKTA_Guard_Sessions::rewrite($source);check(count($r['old'])===8,'eight standard definitions recognized');
check(strpos($r['source'],"define('DB_PASSWORD', 'fixture-only');")!==false,'database password untouched');
check(strpos($r['source'],'// Preserve this comment')!==false,'comments preserved');
check(strpos($r['source'],"require_once ABSPATH . 'wp-settings.php';")!==false,'bootstrap unchanged');
check(strpos($r['source'],"'old-AUTH_KEY'")===false,'old key replaced');
$r2=LNKTA_Guard_Sessions::rewrite($r['source']);check(count(array_unique($r2['old']))===8,'all eight generated secrets unique');
foreach($r2['old'] as $value)check(strlen($value)===128&&ctype_xdigit($value),'generated secret length and safe characters');
refused(function()use($source){LNKTA_Guard_Sessions::rewrite($source."define('AUTH_KEY','duplicate');");},'duplicate definitions refused');
refused(function()use($source){LNKTA_Guard_Sessions::rewrite(str_replace("'old-AUTH_KEY'","getenv('KEY')",$source));},'environment-managed secrets refused');
refused(function()use($source){LNKTA_Guard_Sessions::rewrite(str_replace("define( 'AUTH_KEY', 'old-AUTH_KEY' );","if(true){define('AUTH_KEY','old-AUTH_KEY');}",$source));},'conditional definitions refused');
refused(function(){LNKTA_Guard_Sessions::rewrite('<?php broken syntax !!!');},'invalid PHP refused without execution');
refused(function(){LNKTA_Guard_Sessions::rewrite('<?php // missing keys');},'missing keys refused');
@mkdir(ABSPATH,0700,true);$path=ABSPATH.'wp-config.php';file_put_contents($path,$source);chmod($path,0600);
check(LNKTA_Guard_Sessions::config_path()===$path,'standard configuration located');
check(LNKTA_Guard_Sessions::rotate($path,false)===true,'atomic fixture rotation succeeds');
$new=file_get_contents($path);check($new!==$source&&strpos($new,"'fixture-only'")!==false,'rotation modifies secrets only');
clearstatcache();check((fileperms($path)&0777)===0600,'permissions preserved');
check(count(glob(ABSPATH.'.lnkta-salts-*'))===0,'no temporary secrets left after success');
file_put_contents($path,$source);chmod($path,0400);
refused(function()use($path){LNKTA_Guard_Sessions::rotate($path,false);},'read-only configuration refused');
check(file_get_contents($path)===$source,'protected config unchanged');
chmod($path,0600);refused(function()use($path){LNKTA_Guard_Sessions::rotate($path,true);},'active constants mismatch refused');
check(count(glob(ABSPATH.'.lnkta-salts-*'))===0,'no temporary files after refusal');
unlink($path);file_put_contents(ABSPATH.'target.php',$source);symlink(ABSPATH.'target.php',$path);
refused(function()use($path){LNKTA_Guard_Sessions::rotate($path,false);},'symlink configuration refused');unlink($path);
$_SERVER['REQUEST_METHOD']='GET';denied(function(){LNKTA_Guard_Sessions::handle('signout');},'GET cannot sign users out');
$_SERVER['REQUEST_METHOD']='POST';$GLOBALS['admin']=false;denied(function(){LNKTA_Guard_Sessions::handle('signout');},'non-admin refused');$GLOBALS['admin']=true;
$GLOBALS['nonce']=false;denied(function(){LNKTA_Guard_Sessions::handle('signout');},'invalid CSRF nonce refused');$GLOBALS['nonce']=true;
$_POST=array();denied(function(){LNKTA_Guard_Sessions::handle('signout');},'explicit confirmation required');
$_POST=array('confirm'=>1,'password'=>'bad');$GLOBALS['pw']=false;denied(function(){LNKTA_Guard_Sessions::handle('signout');},'incorrect admin password refused');$GLOBALS['pw']=true;
denied(function(){LNKTA_Guard_Sessions::handle('salts');},'private backup confirmation required');
echo "Session and salt tests passed.\n";
class WP_Session_Tokens {static function destroy_all_for_all_users(){$GLOBALS['dropped']=true;}}
class LNKTA_Security_Guard {static function event(...$a){$GLOBALS['event']=$a;}}
function get_current_user_id(){return 1;}function wp_logout(){$GLOBALS['logged_out']=true;}
function wp_login_url(){return 'https://example.invalid/wp-login.php';}function add_query_arg($k,$v,$u){return $u.'?'.$k.'='.$v;}
function wp_safe_redirect($u){$GLOBALS['redirect']=$u;throw new Stop('redirect');}function esc_html($s){return htmlspecialchars($s);}
file_put_contents($path,$source);chmod($path,0600);$before=hash_file('sha256',$path);
$_POST=array('confirm'=>1,'password'=>'correct');denied(function(){LNKTA_Guard_Sessions::handle('signout');},'signout success ends at login redirect');
check(!empty($GLOBALS['dropped'])&&!empty($GLOBALS['logged_out']),'signout destroys all browser sessions and current cookie');
check(hash_file('sha256',$path)===$before,'signout does not edit config');
foreach(LNKTA_Guard_Sessions::keys() as $key)define($key,'old-'.$key);
$_POST['backup']=1;denied(function(){LNKTA_Guard_Sessions::handle('salts');},'salt success ends at login redirect');
check(hash_file('sha256',$path)!==$before,'salt handler replaces configuration');
check(strpos($GLOBALS['redirect'],'lnkta_guard_done=salts')!==false,'salt success message carried to login');
check(strpos(serialize($GLOBALS['event']),'old-AUTH_KEY')===false,'audit log contains no secrets');
echo "Action success tests passed.\n";
