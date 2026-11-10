<?php
if (!defined('ABSPATH')) { exit; }
/** Best-effort WordPress containment; never a substitute for host isolation. */
final class LNKTA_Guard_Incident {
    private static $cron_dirty=false;
    const CONNECTOR='content-sync-connector/content-sync-connector.php';
    public static function boot() {
        add_filter('rest_pre_dispatch',array(__CLASS__,'rest'),PHP_INT_MAX,3);
        add_filter('pre_update_option_active_plugins',array(__CLASS__,'plugins'),PHP_INT_MAX,2);
        add_filter('pre_schedule_event',array(__CLASS__,'schedule'),PHP_INT_MAX,3);
        add_action('updated_option',array(__CLASS__,'updated'),10,3);
        add_action('shutdown',array(__CLASS__,'shutdown'));
    }
    public static function rest($result,$server,$request) {
        $route='/'.ltrim(rawurldecode($request->get_route()),'/');
        if(preg_match('~^/csc/v1(?:/|$)~i',$route)) return new WP_Error('lnkta_connector_blocked','Unauthorized connector API disabled.',array('status'=>403));
        return $result;
    }
    public static function plugins($value,$old=array()) {
        if(!is_array($value)) return $value;
        if(in_array(self::CONNECTOR,$value,true)) {
            LNKTA_Guard_Hardening::notice('Blocked connector activation entry',array(self::CONNECTOR));
            return array_values(array_diff($value,array(self::CONNECTOR)));
        }
        return $value;
    }
    public static function schedule($pre,$event,$wp_error=false) {
        if(is_object($event) && in_array($event->hook,array('csc_guardian_healthcheck','csc_geogate_refresh'),true)) {
            LNKTA_Guard_Hardening::notice('Blocked connector WordPress scheduled event',array('Hook: '.$event->hook));
            return $wp_error?new WP_Error('lnkta_connector_cron_blocked','Connector scheduling disabled.'):false;
        }
        return $pre;
    }
    public static function updated($name,$old,$new) {
        if($name==='cron') self::$cron_dirty=true;
    }
    public static function shutdown() { if(self::$cron_dirty) self::audit(); }
    public static function cron_inventory($cron) {
        $out=array();
        foreach((array)$cron as $timestamp=>$hooks) {
            if(!is_numeric($timestamp) || !is_array($hooks)) continue;
            foreach($hooks as $hook=>$events) foreach((array)$events as $event) {
                if(!is_array($event)) continue;
                // No timestamps: ordinary rescheduling should not alert. Arguments are hashed, never emailed.
                $key=$hook.'|'.hash('sha256',serialize(array($event['schedule']??false,$event['interval']??0,$event['args']??array())));
                $out[$key]=(string)$hook;
            }
        }
        ksort($out);return $out;
    }
    public static function audit() {
        $current=self::cron_inventory(get_option('cron',array()));
        $old=get_option('lnkta_guard_cron_observed',null);
        if(is_array($old) && $old!==$current) {
            $added=array_values(array_diff_key($current,$old));$removed=array_values(array_diff_key($old,$current));
            LNKTA_Guard_Hardening::notice('WordPress cron inventory changed',array('Added/changed: '.implode(', ',array_slice(array_unique($added),0,20)),'Removed/changed: '.implode(', ',array_slice(array_unique($removed),0,20)),'Normal plugin activity may cause changes. OS/cPanel cron is not covered.'));
        }
        if($old!==$current) update_option('lnkta_guard_cron_observed',$current,false);
        $findings=array();
        foreach(array('csc_identity','csc_recovery_package','csc_persistence_map','csc_provisioned_accounts','csc_placements') as $key) if(get_option($key,null)!==null) $findings[]='Connector database option present: '.$key;
        foreach($current as $hook) if(in_array($hook,array('csc_guardian_healthcheck','csc_geogate_refresh'),true)) $findings[]='Existing connector cron hook: '.$hook;
        if(in_array(self::CONNECTOR,(array)get_option('active_plugins',array()),true)) $findings[]='Connector remains active: hosting cleanup required';
        $findings=array_values(array_unique($findings));
        update_option('lnkta_guard_incident_findings',$findings,false);
        if($findings) LNKTA_Guard_Hardening::notice('Connector persistence requires host cleanup',$findings);
    }
}
LNKTA_Guard_Incident::boot();
