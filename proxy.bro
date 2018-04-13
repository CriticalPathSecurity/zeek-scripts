@load base/utils/site
@load base/frameworks/notice

module HTTP;

export {

        redef enum Notice::Type += {
                notice::Open_Proxy
        };

        global success_status_codes: set[count] = {
                200,
                201,
                202,
                203,
                204,
                205,
                206,
                207,
                208,
                226,
                304
        };

        const private_address_space: set[subnet] = {
             10.0.0.0/8,
             192.168.0.0/16,
             172.16.0.0/12,
             100.64.0.0/10,  # RFC6598 Carrier Grade NAT
             127.0.0.0/8,
             [fe80::]/10,
             [::1]/128,
           } &redef;
}

event http_reply(c: connection, version: string, code: count, reason: string)
        {
        if ( c$id$resp_h in private_address_space &&
             /^[hH][tT][tT][pP]:/ in c$http$uri &&
             c$http$status_code in HTTP::success_status_codes )
                NOTICE([$note=notice::Open_Proxy,
                        $sub=fmt("Severity: 1.0"),
                        $msg=fmt("A local server is acting as an open proxy: %s",
                                 c$id$resp_h),
                        $conn=c,
                        $identifier=cat(c$id$resp_h),
                        $suppress_for=1day]);
        }
