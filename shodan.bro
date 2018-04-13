#Identifier="2018-03-19-0001"
#Iteration="1.0"
#Description="Detects Shodan Requests w/ Established Connections"
#Protocol="ALL"
#CreationDate="2018-03-19"
#LastUpdate="2018-03-19"
#Reference="Non-specific"
#CVSS="0.0"
#Updated by Patrick Kelley (patrick.kelley@criticalpathsecurity.com)

@load base/frameworks/notice

module Shodan;

export {
	redef enum Notice::Type += {
	    notice::Shodan
	};

# List Shodan Server IP Addresses
const shodan_address_space: set [addr] = {
      208.180.20.97,
      198.20.69.74,
      198.20.69.98,
      198.20.70.114,
      198.20.99.130,
      93.120.27.62,
      66.240.236.119,
      71.6.135.131,
      66.240.192.138,
      71.6.167.142,
      82.221.105.6,
      82.221.105.7,
      71.6.165.200,
      188.138.9.50,
      209.126.110.38,
      85.25.103.50,
      85.25.43.94,
      104.236.198.48,
      104.131.0.69,
      162.159.244.38,
  } &redef;

event connection_established(c: connection)
{
if ( c$id$orig_h in shodan_address_space )
	{
	NOTICE([$note=notice::Shodan,
        $conn=c,
	$msg=fmt("%s has initiated a connection from an IP associated with Shodan. The target IP address is %s. The target port is %s.", c$id$orig_h, c$id$resp_h, c$id$resp_p),
	$identifier=cat(c$id$orig_h),
	$suppress_for=1hr]);
	}

}

event connection_established(c: connection)
{
if ( c$id$orig_h in shodan_address_space )
	{
	NOTICE([$note=notice::Shodan,
        $conn=c,
	$msg=fmt("%s has established a connection from an IP associated with Shodan. The target IP address is %s. The target port is %s.", c$id$orig_h, c$id$resp_h, c$id$resp_p),
	$identifier=cat(c$id$orig_h),
	$suppress_for=1hr]);
	}

   }
}
