<?php
error_reporting(E_ALL);define('ABSPATH',__DIR__.'/');
function add_filter(...$a){}function add_action(...$a){}function plugin_basename($f){return 'lnkta-security-guard/'.basename($f);}
$GLOBALS['opts']=array();function get_option($k,$d=false){return $GLOBALS['opts'][$k]??$d;}
require __DIR__.'/../lnkta-security-guard/updater.php';
function check($ok,$label){if(!$ok)throw new Exception('FAIL '.$label);echo 'PASS '.$label."\n";}
check(LNKTA_Guard_Updater::repository()==='pafmobile/lnkta-security-guard','official repository configured');
check(bin2hex(LNKTA_Guard_Updater::key())==='f208f57b47edc12fe9f38ab0386d280c6c9edac27bb3aaf16c07fe08665ba531','uploaded public key configured');
check(LNKTA_Guard_Updater::ready()===function_exists('sodium_crypto_sign_verify_detached'),'native signature verification required');
check(LNKTA_Guard_Updater::download('unchanged','https://example.invalid/other.zip',null,array('plugin'=>'other/plugin.php'))==='unchanged','unrelated plugin downloads preserved');
check(LNKTA_Guard_Updater::automatic(true,(object)array('plugin'=>'other/plugin.php'))===true,'unrelated automatic update choice preserved');
check(LNKTA_Guard_Updater::automatic(true,(object)array('plugin'=>LNKTA_Guard_Updater::file()))===false,'own automatic updates wait for setup');
check(LNKTA_Guard_Updater::verify(array('payload'=>'bad','signature'=>'bad'),str_repeat('x',32),'user/repo')===false,'malformed signed release rejected');
// The isolated WASM PHP build lacks sodium. This shim exercises verifier call paths;
// real Ed25519 signing/verification is separately exercised with Python cryptography.
if(!function_exists('sodium_crypto_sign_keypair')) {
    function sodium_crypto_sign_keypair(){return str_repeat('k',32);}
    function sodium_crypto_sign_publickey($pair){return $pair;}
    function sodium_crypto_sign_secretkey($pair){return $pair;}
    function sodium_crypto_sign_detached($payload,$secret){return hash('sha512',$payload.$secret,true);}
    function sodium_crypto_sign_verify_detached($sig,$payload,$key){return hash_equals(hash('sha512',$payload.$key,true),$sig);}
    echo "Verifier shim used: native PHP sodium integration requires host testing.\n";
}
$pair=sodium_crypto_sign_keypair();$key=sodium_crypto_sign_publickey($pair);$secret=sodium_crypto_sign_secretkey($pair);
$m=array('repository'=>'user/repo','slug'=>'lnkta-security-guard','version'=>'1.5.1','requires_php'=>'7.4','requires_wp'=>'6.0','sha256'=>str_repeat('a',64),'package_url'=>'https://github.com/user/repo/releases/download/v1.5.1/lnkta-security-guard-v1.5.1.zip');
function sign($m,$secret){$p=json_encode($m);return array('payload'=>base64_encode($p),'signature'=>base64_encode(sodium_crypto_sign_detached($p,$secret)));}
$e=sign($m,$secret);check(LNKTA_Guard_Updater::verify($e,$key,'user/repo')===$m,'valid signed release accepted');
check(LNKTA_Guard_Updater::verify($e,str_repeat('x',32),'user/repo')===false,'wrong signer rejected');
$bad=$e;$bad['payload']=base64_encode(str_replace('1.5.1','1.5.2',base64_decode($e['payload'])));check(LNKTA_Guard_Updater::verify($bad,$key,'user/repo')===false,'modified metadata rejected');
check(LNKTA_Guard_Updater::verify($e,$key,'different/repo')===false,'release from another repository rejected');
$bad=$m;$bad['package_url']='https://evil.invalid/payload.zip';check(LNKTA_Guard_Updater::verify(sign($bad,$secret),$key,'user/repo')===false,'package outside exact GitHub release path rejected even if signed');
$bad=$m;$bad['version']='../../other';check(LNKTA_Guard_Updater::verify(sign($bad,$secret),$key,'user/repo')===false,'invalid release version rejected');
$path=__DIR__.'/hash-fixture.zip';file_put_contents($path,'test-package');check(LNKTA_Guard_Updater::hash_ok($path,hash('sha256','test-package')),'matching package hash accepted');check(!LNKTA_Guard_Updater::hash_ok($path,str_repeat('a',64)),'changed package hash rejected');unlink($path);
$wp_version='6.5';check(LNKTA_Guard_Updater::compatible($m),'compatible environment accepted');$m['requires_wp']='999.0';check(!LNKTA_Guard_Updater::compatible($m),'incompatible WordPress rejected');
echo "Signed update tests passed.\n";
