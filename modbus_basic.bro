#Protocol="MODBUS"
#CreationDate="2018-11-20"
#Modbus Diagnostics function detection script by Jeff Barron (jeff.barron@criticalpathsecurity.com)



@load base/frameworks/files
@load base/frameworks/notice
@load base/protocols/modbus

export {
redef enum Notice::Type +=
	{
    notice::ModBus_Diagnostics_Function,
    notice::Unknown_Function
};

}
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) 
	{
	if ( ! c?$modbus )
		{
		c$modbus = [$ts=network_time(), $uid=c$uid, $id=c$id];
		}
		
	 if (headers$function_code == 8)
	    { 
	     NOTICE([$note=notice::ModBus_Diagnostics_Function,
			 $identifier=cat(c$id$orig_h) 
			 $msg=fmt("Modbus Diagnostics function has been issued!"),
			 $sub=fmt("Stage:Exploitation"), 
			 $conn=c]); 
	    }
    }
