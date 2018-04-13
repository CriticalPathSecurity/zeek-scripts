@load base/frameworks/notice

module DNS_Query_Notice;

export {

        redef enum Notice::Type += {
                notice::DNS_Request_To_Unauthorized_Source
        };

        # List DNS servers here
        const dns_servers: set[addr] = {
        10.0.0.30,
        10.0.12.241,
        10.100.0.30,
        172.0.0.1,
	      10.0.12.255,
        224.0.0.252,
	} &redef;

	const subnet_exclude: set[subnet] = {
        192.168.2.0/24, # Devices in VLANS (IOT) or Guest Wireless where Domain Rules Aren't Enforced
        } &redef;

        # List any source addresses that should be excluded
        const dns_server_exclude: set[addr] = {
        192.168.0.1,
        192.168.50.1,
        10.0.0.1,
        172.0.0.1,
        } &redef;

}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
        {
        if ( c$id$resp_h !in dns_server_exclude && c$id$resp_h !in dns_servers )
                {
                NOTICE([$note=notice::DNS_Request_To_Unauthorized_Source,
                $msg="DNS query request sent to Unauthorized DNS Source", $conn=c,
                $sub=fmt("Severity: 1.0"),
                $identifier=cat(c$id$orig_h),
                $suppress_for=1hr]);
                }
        }
