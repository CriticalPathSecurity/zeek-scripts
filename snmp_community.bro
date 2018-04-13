@load base/frameworks/notice

module SNMP_DEFAULT;

export {
        redef enum Notice::Type += {
                notice::SNMP_DEFAULT::Default_Community_Strings
        };
}

const snmp_strings =
    /public*/
    |/private*/
&redef;

event snmp_get_request(c: connection, is_orig: bool, header:  SNMP::Header, pdu: SNMP::PDU)
        {
        if (snmp_strings in c$snmp$community)
                {
                NOTICE([$note=notice::SNMP_DEFAULT::Default_Community_Strings,
                $conn=c,
                $msg=fmt("%s is communicating with default SNMP community strings (%s) with %s.", c$id$orig_h, c$snmp$community, c$id$resp_h),
                $sub=fmt("Severity: 8.6"),
                $identifier=cat(c$id$resp_h),
                $suppress_for=1hr]);
                }
        }
