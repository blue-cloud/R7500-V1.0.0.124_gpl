function checkvpn(cf)
{
	var count =0;
	var int_port = parseInt(cf.vpn_port.value,10);
	if(cf.enable_vpn.checked == true)
	{
		if(old_endis_ddns != "1" && (old_wan_assign == "0" || (old_wan_assign == "1" && select_basic != "1")))
		{
			alert("$no_static_ip_ddns");
			return false;
		}
		if(old_endis_ddns != "1" && old_wan_assign == "1" && select_basic == "1")
			if(confirm("$no_ddns") == false){
				cf.enable_vpn.checked = false;
				return false;
			}
		if(ipv6_type == "autoDetect" || ipv6_type == "pppoe" || ipv6_type == "dhcp" || ipv6_type == "fixed" || ipv6_type == "bridge" || ipv6_type == "6to4" || ipv6_type == "autoConfig")
		{
			alert("$no_enable_vpn_ipv6");
			return false;
		}
		
	
	}
	if(int_port > 65534 )
	{
		alert("$serv_port_limit");
		return false;
	}

	
	if(cf.enable_vpn.checked == true)
		cf.hidden_enable_vpn.value=1;
	else
		cf.hidden_enable_vpn.value=0;
	if(cf.vpn_type[0].checked == true)
		cf.hidden_vpn_type.value="udp";
	else if(cf.vpn_type[1].checked == true)
		cf.hidden_vpn_type.value="tcp";
	cf.hidden_vpn_port.value=cf.vpn_port.value;
	if(cf.vpn_access[0].checked == true)
		cf.hidden_vpn_access.value="auto";
	else if(cf.vpn_access[1].checked == true)
		cf.hidden_vpn_access.value="all";
	else if(cf.vpn_access[2].checked == true)
		cf.hidden_vpn_access.value="home";
	if((cf.enable_vpn.checked == true)&&(check_all_port(int_port, cf.hidden_vpn_type.value) == false))
        {
                alert("$invalid_port_used");
                return false;
        }
	if(cf.enable_vpn.checked == true && backup_rsp == "")
	{
		cf.hidden_backup_rspToPing.value = cf.rspToPing_value;
	}
	if((cf.hidden_vpn_type.value!=type || cf.hidden_vpn_port.value != port || cf.hidden_vpn_access.value != access_mode) && cf.hidden_enable_vpn.value == 1)
	{
		alert("$warn_change_vpn_config");
	}

	return true;

}

function checkdownload(cf, num)
{
	if(vpn_enable == "0")
	{
		alert("$no_enable_vpn");
		return false;
	}
	if(old_endis_ddns != "1")
        {
                alert("$no_ddns_config_file");
        }
	if( num == 1)
		cf.download_button_type.value="windows";		
	else if(num == 2)
		cf.download_button_type.value="nonwindows";
	cf.action="/apply.cgi?/vpn_frame.htm timestamp="+ts;
	cf.submit_flag.value="vpn_compress_conf";
	return true;
}

function check_all_port(int_used_port, type)
{
	var ret=true;
	if(check_vpn_port_range("forwardingArray", forward_array_num, int_used_port, type) == false)
		ret = false;

	if(check_vpn_port_range("triggeringArray", trigger_array_num, int_used_port, type) == false)
		ret = false;

	if(check_vpn_port_range("upnpArray", upnp_array_num, int_used_port, type) == false)
		ret = false;
	//check USB ready share port, only use TCP
	if( usb_router_flag == 1)
	{
		if(type != "UDP")
		{
			if(check_readyshare_port(int_used_port, int_used_port, "ALL") == false)
			{
				ret = false;
			}

		}
	}

	//check with remote, only use TCP
	if(endis_remote=="1" && type != "UDP" && parseInt(remote_port) == int_used_port) //15873: remote only use TCP
               ret=false;
	
	//enable ntp, only use UDP
	if(int_used_port == 123 && endis_ntp == "1" && type != "TCP")
       		ret = false; 
	
	//enable upnp, only use UDP
	if(int_used_port == 1900 && endis_upnp == "1" && type != "TCP")
       		ret = false; 

	//enable bigpond   15873: bigpond only use UDP
	if(int_used_port == 5050 && info_get_wanproto == "bigpond" && type != "TCP")
       		ret = false; 

	
	return ret;
	
}

function check_vpn_port_range(name, length, port_using, type)
{
        var i, str, each_info, sertype, startport, endport, serflag;
        for(i=1; i<=length; i++)
        {
                switch(name)
                {
                        case "forwardingArray":
                                str = eval(name + i);
                                each_info=str.split(' ');
                                sertype=each_info[1];
                                startport=each_info[2];
                                endport=each_info[3];
                                break;
                        case "triggeringArray":
                                str = eval(name + i);
                                each_info=str.split(' ');
                                sertype=each_info[5];
                                startport=each_info[6];
                                endport=each_info[7];
                                break;
                        case "upnpArray":
                                str = eval(name + i);
                                each_info=str.split(';');
                                sertype=each_info[1];
                                startport=each_info[3];
                                endport=each_info[3];
                                break;
                        default:
                                break;
                }

                if(sertype == type || sertype == "TCP/UDP")
                {
                        if(parseInt(startport)<=parseInt(port_using) && parseInt(endport)>=parseInt(port_using))
                                return false;
                }
        }

        return true;
}
