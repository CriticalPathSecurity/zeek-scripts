#Protocol="SMB"
#CreationDate="2017-01-03"
#Updated by Patrick Kelley (patrick.kelley@criticalpathsecurity.com)

@load base/frameworks/files
@load base/frameworks/notice
@load base/protocols/smb
@load base/frameworks/sumstats
@load base/protocols/http
@load base/frameworks/intel

export {
redef enum Notice::Type +=
	{
    notice::SMB_Administrative_Share,
    notice::webconfigattack,
    notice::SMB_Conficker,
		notice::SMB_Suspicious_Hostname,
		notice::SMB_Hostname_Like_Known_Attacker
	};

const bruteforce_threshold: double = 500 &redef;
const bruteforce_measurement_interval = 1mins &redef;
const smb_ports: set[port] = {445/tcp, 137/udp, 139/udp} &redef;
const port_number: set[port] = {445/udp, 445/tcp} &redef;
const scan_limit: double = 30 &redef;
const scan_timeout = 1 mins &redef;
const ignore_guessers: table[subnet] of subnet &redef;


const winrm_ports: set[port] = {
                5985/tcp,# WinRM/Powershell
                5986/tcp,# WinRM/Powershell
                } &redef;

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{

if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
{
NOTICE([$note=notice::SMB_Administrative_Share, $msg=fmt("Potentially Malicious Use of an Administative Share"), $sub=fmt("%s",path), $conn=c]);
}
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
{
if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
{
NOTICE([$note=notice::SMB_Administrative_Share, $msg=fmt("Potentially Malicious Use of an Administative Share"), $sub=fmt("%s",path), $conn=c]);
}
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
{
if ("web.config" in path || "inetpub" in path)
{
NOTICE([$note=notice::SMB_Administrative_Share,
$msg=fmt("%s Potential abuse of IIS against %s - (%s).", c$id$orig_h, c$id$resp_h, path),
$conn=c,
$identifier=cat(c$id$orig_h)]);
}
}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{
if ("web.config" in path || "inetpub" in path)
{
NOTICE([$note=notice::webconfigattack,
$msg=fmt("%s Potential abuse of IIS against %s - (%s).", c$id$orig_h, c$id$resp_h, path),
$conn=c,
$identifier=cat(c$id$orig_h)]);
}
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
if ("web.config" in unescaped_URI || "inetpub" in unescaped_URI || "aspnet_regiis" in unescaped_URI || c$id$resp_p in winrm_ports)
{
NOTICE([$note=notice::webconfigattack,
$msg=fmt("%s Potential abuse of IIS against %s - (%s).", c$id$orig_h, c$id$resp_h, unescaped_URI),
$conn=c,
$identifier=cat(c$id$orig_h)]);
}
}
}

event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="scan.conficker.attempts", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=5];
	SumStats::create([$name="detect-conficker-scanning",
	                  $epoch=scan_timeout,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scan.conficker.attempts"]$sum;
	                  	},
	                  $threshold=scan_limit,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scan.conficker.attempts"];
	                  	local sub_msg = fmt("Sampled servers: ");
	                  	local samples = r$samples;
	                  	for ( i in samples )
	                  		{
	                  		if ( samples[i]?$str )
	                  			sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
	                  		}

	                  	NOTICE([$note=notice::SMB_Conficker,
	                  	        $msg=fmt("%s scanning for vulnerable workstations (seen in %d connections).", key$host, r$num),
	                  	        $sub=sub_msg,
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event new_connection(c: connection)
	{
	local id = c$id;

	if ( c$id$resp_p in port_number )
		SumStats::observe("scan.conficker.attempts", [$host=id$orig_h], [$str=cat(id$resp_h)]);
	}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
	{

	# strip out first 3 characters of workstation value to be compared to company convention
	local strcheck = sub_bytes(request$workstation, 1, 3);


	# value of the comparison of the two strings
	local comp_str = strcmp(strcheck, "YOURENTERPRISENAME");

	        # If the comparison of the strings stored in comp_str are not the same, generate a notice.
	        if (comp_str != 0 )
	        {
	        NOTICE([$note=notice::SMB_Suspicious_Hostname,
					$msg=fmt("Potential Lateral Movement Activity - Invalid Hostname (%s) using Domain Credentials",request$workstation),
					$conn=c,
					$identifier=cat(c$id$orig_h)]);
	      }
}

## 0-day malware script detection
event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
	{

	# strip out first 3 characters of workstation value to be compared to company convention
	local strcheck = sub_bytes(request$workstation, 1, 20);


	# value of the comparison of the two strings
	local comp_str = strcmp(strcheck, "Server2009@SMB3.local");

	        # If the comparison of the strings stored in comp_str are not the same, generate a notice.
	        if (comp_str == 0 )
	        {
	        NOTICE([$note=notice::SMB_Hostname_Like_Known_Attacker,
					$msg=fmt("Potential Lateral Movement Activity - Known Attacker Hostname (%s) attempt 0-Day Exploit",request$workstation),
					$conn=c,
					$identifier=cat(c$id$orig_h)]);
	      }
}
