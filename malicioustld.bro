# UID 2018-06-12-0001
# Developed at Critical Path Security by Patrick Kelley
# Detects DNS and HTTP Requests to Malicious TLDs
# Version 1.0

@load base/frameworks/notice

module MaliciousTLD;

export {
      redef enum Notice::Type += {
                 notice::MaliciousTLD
      };

const malicious_tld =
          /\.men$/
          |/\.gdn$/
          |/\.work$/
          |/\.click$/
          |/\.loan$/
          |/\.top$/
          |/\.cf$/
          |/\.gg$/
          |/\.ml$/
          |/\.ga$/
&redef;
}

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
        {
        if ( malicious_tld in unescaped_URI )
                {
                NOTICE([$note=notice::MaliciousTLD,
                $conn=c,
                $msg=fmt("%s sent a http request to (%s), which is listed as a potentially malicious TLD. URI is (%s)", c$id$orig_h, c$id$resp_h, unescaped_URI),
                $sub=fmt("Severity: 1.0"),
                $identifier=cat(c$id$orig_h)]);
                }
        }

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
                {
        if ( malicious_tld in query )
                          {
                          NOTICE([$note=notice::MaliciousTLD,
                          $conn=c,
                          $msg=fmt("%s just received a DNS query for a domain in a potentially malicious TLD - %s.", c$id$orig_h, query),
                          $identifier=cat(c$id$orig_h),
                          $sub=fmt("Severity: 1.0"),
                          $suppress_for=1hr]);
                          }
                }
