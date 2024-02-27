import logging

from palo_alto_firewall_analyzer.core import Detail

def get_value(data):
    if data is None:
        data = ""
    
    return data

def parsed_details(details):
    
    detail = Detail(
        policy_type=get_value(details.get('policy_type')),
        policy_name=get_value(details.get('policy_name')),
        device_group=get_value(details.get('device_group')),
        entry_type=get_value(details.get('entry_type')),
        entry_name=get_value(details.get('entry_name')),
        entry_value=get_value(details.get('entry_value')),
        rule_type=get_value(details.get('rule_type')),
        rule_name=get_value(details.get('rule_name')),
        protocol=get_value(details.get('protocol')),
        port=get_value(details.get('port')),
        allowed_group_profiles=get_value(details.get('allowed_group_profiles')),
        group_profile_setting=get_value(details.get('group_profile_setting')),
        address=get_value(details.get('address')),
        fqdn=get_value(details.get('fqdn')),
        ip=get_value(details.get('ip')),
        ip_mask=get_value(details.get('ip_mask')),
        loc=get_value(details.get('loc')),
        shadowing_address_name=get_value(details.get('shadowing_address_name')),        
        mandated_log_profile=get_value(details.get('mandated_log_profile')),
        log_setting=get_value(details.get('log_setting')),        
        object_entry_name=get_value(details.get('object_entry_name')),
        policy_entry_name=get_value(details.get('policy_entry_name')),
        zone_type=get_value(details.get('zone_type')),
        zones=get_value(details.get('zones')),
        extra=get_value(details.get('extra'))
    )
    
    return detail
    

def get_json_detail(detail):
    json_detail={
                    "policy_type":detail.policy_type,
                    "policy_name":detail.policy_name,
                    "device_group":detail.device_group,
                    "entry_type":detail.entry_type,
                    "entry_name":detail.entry_name,
                    "rule_type":detail.rule_type,
                    "rule_name":detail.rule_name,
                    "protocol":detail.protocol,
                    "port":detail.port,
                    "allowed_group_profiles":detail.allowed_group_profiles,
                    "group_profile_setting": detail.group_profile_setting,
                    "address": detail.address,
                    "fqdn": detail.fqdn,
                    "ip":detail.ip,
                    "ip_mask":detail.ip_mask,
                    "loc":detail.loc,
                    "shadowing_address_name":detail.shadowing_address_name,
                    "mandated_log_profile":detail.mandated_log_profile,
                    "log_setting":detail.log_setting,                    
                    "object_entry_name":detail.object_entry_name,
                    "policy_entry_name":detail.policy_entry_name,
                    "zone_type":detail.zone_type,
                    "zones":detail.zones,
                    "extra":detail.extra
                    }
    
    return json_detail
