@load base/frameworks/notice

module Emotet;

export {
      redef enum Notice::Type += {
                 notice::Emotet
    ;

const emotet_host =
          /nobleduty.*/
          |/Tradeque.*/
          |/medicalciferol.*/
          |/lik0sal.*/
          |/comeontrk.*/
          |/csuwbru.*/
&redef;
}


event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
                {

        if ( emotet_host in query )
                          {
                          NOTICE([$note=notice::Emotet,
                          $conn=c,
                          $msg=fmt("%s just received a DNS query response related to Emotet - %s.", c$id$orig_h, query),
                          $identifier=cat(c$id$orig_h),
                          $sub=fmt("Severity: 1.0"),
                          $suppress_for=1hr]);
                          }
                }
