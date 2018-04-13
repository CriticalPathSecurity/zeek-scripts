@load base/frameworks/notice

module Default_Credential_Usage;

export {
      redef enum Notice::Type += {
                 notice::Default_Credential_Usage
    };

const Hisilicon_listening_ports: set[port] = {
    9527/tcp,
   } &redef;

const GM8182_listening_ports: set[port] = {
    88/tcp,
   } &redef;

const GM8182_credentials =
    /GM8182*/
    |/test*/
&redef;

const avtech =
    /CloudSetup.cgi?exefile*/
&redef;

const GAP_Mercury =
          /GAPM-*/
&redef;

const vstarcam =
          /20150602*/
          |/juantech*/
          |/7ujMko0admin*/
          |/hunt5759*/
          |/ivdev*/
&redef;

const mikrotik =
          /passw0rd*/
          |/1234567890*/
          |/admin123*/
          |/P@55w0rd!*/
          |/admin1234*/
          |/operator*/
          |/monitor*/
&redef;

const actiontec =
          /CenturyL1nk*/
          |/CTLSupport12*/
          |/QwestM0dem*/
          |/ho4uku6at*/
          |/epicrouter*/
          |/nE7jA%5m*/
          |/zyad1234*/
&redef;

const hp_switch =
          /manager*/
          |/operator*/
&redef;

const davolink =
          /davo*/
          |/drc*/
&redef;

const montavista =
          /service*/
          |/admin*/
          |/ftp*/
&redef;

const commonaccounts =
          /service*/
          |/admin*/
          |/ftp*/
          |/csanders*/
&redef;

const hikvision =
          /12345*/
          |/888888*/
          |/54321*/
          |/123456*/
          |/000000*/
          |/00000*/
          |/1234*/
          |/1*/
          |/123*/
          |/1234567890*/
          |/321*/
          |/1234567*/
          |/123123*/
          |/696969*/
          |/4321*/
          |/1111*/
          |/1234qwer*/
          |/password*/
          |/pu*/
          |/0000*/
          |/admin*/
          |/5555*/
          |/7777*/
          |/11111*/
          |/654321*/
          |/hikvision*/
          |/123456789abc*/
          |/12345*/
          |/1234*/
          |/1234567890*/
          |/admin1234*/
          |/123456*/
          |/admin*/
          |/666666*/
          |/654321*/
          |/1111*/
          |/admin1*/
          |/22222*/
          |/power*/
          |/abc123*/
          |/11111111*/
          |/2222*/
          |/0000*/
          |/4321*/
          |/123456789abc*/
          |/12345*/
          |/hikvision*/
&redef;

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
        {
        if ( avtech in unescaped_URI )
                {
                NOTICE([$note=notice::Default_Credential_Usage,
                $conn=c,
                $msg=fmt("%s sent a http request to (%s) with an executable. URI is (%s)", c$id$orig_h, c$id$resp_h, unescaped_URI),
                $sub=fmt("Severity: 5.0"),
                $identifier=cat(c$id$orig_h)]);
                          }
                }

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
          {
          if ( GAP_Mercury in unescaped_URI )
                  {
                  NOTICE([$note=notice::Default_Credential_Usage,
                  $conn=c,
                  $msg=fmt("%s sent a http request to (%s) with default credentials. URI is (%s)", c$id$orig_h, c$id$resp_h, unescaped_URI),
                  $sub=fmt("Severity: 5.0"),
                  $identifier=cat(c$id$orig_h)]);
                            }
                  }

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
          {
          if ( GM8182_credentials in unescaped_URI && c$id$resp_p in GM8182_listening_ports )
                  {
                  NOTICE([$note=notice::Default_Credential_Usage,
                  $conn=c,
                  $msg=fmt("%s sent a http request to (%s) with default credentials - GM8182. URI is (%s)", c$id$orig_h, c$id$resp_h, unescaped_URI),
                  $sub=fmt("Severity: 5.0"),
                  $identifier=cat(c$id$orig_h)]);
                            }
                  }

event http_header(c:connection,is_orig:bool,name:string,value:string)
	{
	if (/AUTHORIZATION/ in name && /Basic/ in value && /Credentials/ in name && GM8182_credentials in c$http$username)
		{
			NOTICE([$note=notice::Default_Credential_Usage,
      $conn=c,
      $msg=fmt("%s is using basic authentication attacks against - %s. Likely a GM8182. Credentials are %s.", c$id$orig_h, c$id$resp_h, value),
      $identifier=cat(c$id$orig_h),
      $sub=fmt("Severity: 6.4"),
      $suppress_for=1hr]);
		}
	}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
if ( c$id$resp_p in Hisilicon_listening_ports )	{
	        NOTICE([$note=notice::Default_Credential_Usage,
          $conn=c,
          $msg=fmt("%s is using atypical telnet sessions for a Hisilicon camera - %s.", c$id$orig_h, c$id$resp_h),
          $identifier=cat(c$id$orig_h),
					$sub=fmt("Severity: 6.4"),
			    $suppress_for=1hr]);
    }
}

event http_header(c:connection,is_orig:bool,name:string,value:string)
	{
	if (/AUTHORIZATION/ in name && /Basic/ in value && /Credentials/ in name && vstarcam in c$http$password)
		{
			NOTICE([$note=notice::Default_Credential_Usage,
      $conn=c,
      $msg=fmt("%s is using basic authentication attacks against - %s. Likely a vstarcam. Credentials are %s.", c$id$orig_h, c$id$resp_h, value),
      $identifier=cat(c$id$orig_h),
      $sub=fmt("Severity: 6.4"),
      $suppress_for=1hr]);
		}
	}

event http_header(c:connection,is_orig:bool,name:string,value:string)
	{
	if (/AUTHORIZATION/ in name && /Basic/ in value && /Credentials/ in name && c$http$password == "admin" && mikrotik in c$http$password)
		{
			NOTICE([$note=notice::Default_Credential_Usage,
      $conn=c,
      $msg=fmt("%s is using basic authentication attacks against - %s. Likely a MikroTik. Credentials are %s.", c$id$orig_h, c$id$resp_h, value),
      $identifier=cat(c$id$orig_h),
      $sub=fmt("Severity: 6.4"),
      $suppress_for=1hr]);
		}
	}

event http_header(c:connection,is_orig:bool,name:string,value:string)
	{
	if (/AUTHORIZATION/ in name && /Basic/ in value && /Credentials/ in name && davolink in c$http$password && davolink in c$http$password)
		{
			NOTICE([$note=notice::Default_Credential_Usage,
      $conn=c,
      $msg=fmt("%s is using basic authentication attacks against - %s. Likely a DavoLink. Credentials are %s.", c$id$orig_h, c$id$resp_h, value),
      $identifier=cat(c$id$orig_h),
      $sub=fmt("Severity: 6.4"),
      $suppress_for=1hr]);
		}
	}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
if ( actiontec in password && user == "admin" )	{
	        NOTICE([$note=notice::Default_Credential_Usage,
          $conn=c,
          $msg=fmt("%s is using telnet sessions for a Actiontec router (%s) with default credentials - %s.", c$id$orig_h, c$id$resp_h, password),
          $identifier=cat(c$id$orig_h),
					$sub=fmt("Severity: 6.4"),
			    $suppress_for=1hr]);
    }
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
if ( hp_switch in password )	{
	        NOTICE([$note=notice::Default_Credential_Usage,
          $conn=c,
          $msg=fmt("%s is using telnet sessions for a HP switch (%s) with default credentials - %s / %s.", c$id$orig_h, c$id$resp_h, user, password),
          $identifier=cat(c$id$orig_h),
					$sub=fmt("Severity: 6.4"),
			    $suppress_for=1hr]);
    }
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
if ( montavista in password && user == "admin" )	{
	        NOTICE([$note=notice::Default_Credential_Usage,
          $conn=c,
          $msg=fmt("%s is using telnet sessions for a MontaVista device (%s) with default credentials - %s / %s.", c$id$orig_h, c$id$resp_h, user, password),
          $identifier=cat(c$id$orig_h),
					$sub=fmt("Severity: 6.4"),
			    $suppress_for=1hr]);
    }
}

event ftp_request(c:connection, command:string, arg:string)
{
if (commonaccounts in arg){
          NOTICE([$note=notice::Default_Credential_Usage,
          $conn=c,
          $msg=fmt("%s is using ftp sessions for a network device (%s) with default credentials - %s / %s.", c$id$orig_h, c$id$resp_h, c$ftp$user, arg),
          $identifier=cat(c$id$orig_h),
					$sub=fmt("Severity: 6.4"),
			    $suppress_for=1hr]);

    }
}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
                {

        if ( "netween.co.kr" in query )
                          {
                          NOTICE([$note=notice::Default_Credential_Usage,
                          $conn=c,
                          $msg=fmt("%s just received a DNS query response related to netween - %s.", c$id$orig_h, query),
                          $identifier=cat(c$id$orig_h),
                          $sub=fmt("Severity: 1.0"),
                          $suppress_for=1hr]);
                          }
                }

}
