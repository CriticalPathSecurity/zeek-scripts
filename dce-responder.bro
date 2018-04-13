@load base/frameworks/notice

module dce_rpc;

export {

        redef enum Notice::Type += {
                notice::DCERPC
        };

### Must be set for proper classification
const domain_controllers: set[addr] = {
192.168.0.2,
} &redef;

const dce_rpc_commands =
  /DRSGetNCChanges.*/
&redef;

const dce_crack_commands =
  /DRSCrackNames.*/
&redef;


event dce_rpc_request(c: connection, fid: count, opnum: count, stub_len: count) &priority=5
{
  if ( ! c?$dce_rpc )
      return;
  if ( ! c$dce_rpc?$operation )
      return;
  if ( c$id$orig_h !in domain_controllers && dce_rpc_commands in c$dce_rpc$operation )
                {
                NOTICE([$note=notice::DCERPC,
                $conn=c,
                $msg=fmt("%s requested a dce_rpc command from %s. The command was %s. %s is not on the allowed list", c$id$orig_h, c$id$resp_h, c$dce_rpc$operation, c$id$orig_h),
                $sub=fmt("Severity: 3.0"),
                $identifier=cat(c$id$orig_h)]);
                }
}
event dce_rpc_request(c: connection, fid: count, opnum: count, stub_len: count) &priority=5
{
  if ( ! c?$dce_rpc )
      return;
  if ( ! c$dce_rpc?$operation )
      return;
  if ( dce_crack_commands in c$dce_rpc$operation )
                {
                NOTICE([$note=notice::DCERPC,
                $conn=c,
                $msg=fmt("%s requested a dce_rpc command from %s. The command was %s.", c$id$orig_h, c$id$resp_h, c$dce_rpc$operation),
                $sub=fmt("Severity: 8.0"),
                $identifier=cat(c$id$orig_h)]);
                }
}

}
