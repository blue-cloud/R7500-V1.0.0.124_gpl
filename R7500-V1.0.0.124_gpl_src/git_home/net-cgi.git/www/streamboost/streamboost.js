function wmmMain()
{
	location.href="QOS_wmm.htm";
}

function qos_advanced()
{
	location.href="QOS_advanced.htm";
}

function qos_basic()
{
	location.href="QOS_basic.htm";
}

function format_version(vir)
{
	var head = vir.substring(0, 4);
	var middle = vir.substring(4, 8);
	var tail = vir.substring(15);
	return parseInt(head) % 2013 + "." + middle + "." + tail;
}

function format_time(time)
{
	var year = time.substring(0, 4);
	var mouth = time.substring(4, 6);
	var day = time.substring(6);
	var mon_eng = new Array("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December");
	return mon_eng[parseInt(mouth)-1]+" "+day+", "+year;
}

function confirm_dialox()
{
	var cf=document.forms[0];
	//if(cf.help_improve.checked == true && cf.streamboostEnable.checked == true) {
		window.open('QOS_improve_service.htm','newwindow','resizable=no,scrollbars=no,toolbar=no,menubar=no,status=no,location=no,alwaysRaised=yes,z-look=yes,width=800,height=600,left=200,top=100').focus();
	//}
}

function setSpeed(num)
{
	if(num == "1") {
		alert("$set_bandwidth_warning");
		document.getElementById("speedtest_radio").style.display = "none";
		document.getElementById("option1").style.display = "none";
		document.getElementById("option2").style.display = "none";
		document.getElementById("define_radio1").style.display = "";
		document.getElementById("define_radio2").style.display = "";
	} else {
		document.getElementById("speedtest_radio").style.display = "";
		document.getElementById("option1").style.display = "";
		document.getElementById("option2").style.display = "";
		document.getElementById("define_radio1").style.display = "none";
		document.getElementById("define_radio2").style.display = "none";
	}
}

function clearNoNum(obj)
{
	obj.value = obj.value.replace(/[^\d.]/g,"");
	obj.value = obj.value.replace(/^\./g,"");
	obj.value = obj.value.replace(/\.{2,}/g,".");
	obj.value = obj.value.replace(".","$#$").replace(/\./g,"").replace("$#$",".");
	obj.value = obj.value.replace(/^(\-)*(\d+)\.(\d\d\d).*$/,'$1$2.$3');
}

function check_qos_apply(cf)
{
	var cf=document.forms[0];
	var streamboost_uplink=parseFloat(cf.uplink_value.value).toFixed(2);
	var streamboost_downlink=parseFloat(cf.downlink_value.value).toFixed(2);

	if(cf.streamboostEnable.checked == true)
		cf.hid_streamboost_enable.value=1;
	else
		cf.hid_streamboost_enable.value=0;

	if(cf.detect_database.checked == true)
		cf.hid_detect_database.value=1;
	else{
		cf.hid_detect_database.value=0;
		cf.hid_update_agreement.value="1";
	}

	if(cf.help_improve.checked == true)
		cf.hid_improve_service.value=1;
	else
		cf.hid_improve_service.value=0;

	if(cf.sel_bandwidth[0].checked == true)
		cf.hid_bandwidth_type.value=0;
	else
		cf.hid_bandwidth_type.value=1;
	if(cf.streamboostEnable.checked == true && cf.detect_database.checked == true && (first_flag != "0" ||(first_flag == "0" && cf.sel_bandwidth[0].checked == false)) && update_agreement == "1")
		if(confirm("$share_mac_warn") == false){
			cf.detect_database.checked = false;
			cf.hid_detect_database.value=0;
			cf.hid_update_agreement.value = "1";			
		}else
			cf.hid_update_agreement.value = "0";
	if(cf.streamboostEnable.checked == true && cf.sel_bandwidth[0].checked == true)
	{
		if(first_flag == "0") {
			if(confirm("$warning_bandwidth") == false)
				return false;
			else {
				if(internet_status == "0"){
					alert("$internet_down");
					return false;
				}
				cf.hid_first_flag.value="1";
				parent.ookla_speedtest_flag == 1;
			}	
		} else {
			cf.hid_first_flag.value="2";
		}

		if(cf.uplink_value.value == "")
			cf.hid_streamboost_uplink.value="";
		else if(streamboost_uplink<0.10 || streamboost_uplink>1000.00)
		{
			alert("$range_error");
			return false;
		}
		else
			cf.hid_streamboost_uplink.value=parseInt((cf.uplink_value.value)*1000000/8);

		if(cf.downlink_value.value == "")
			cf.hid_streamboost_downlink.value="";
		else if(streamboost_downlink<0.10 || streamboost_downlink>1000.00)
		{
			alert("$range_error");
			return false;
		}
		else
			cf.hid_streamboost_downlink.value=parseInt((cf.downlink_value.value)*1000000/8);
	} else if(cf.streamboostEnable.checked == true && cf.sel_bandwidth[1].checked == true) {
		if(internet_status == "0"){
			alert("$internet_down");
			return false;
		}
		if(cf.uplink_value.value == "" || cf.downlink_value.value == "")
		{
			alert("$max_required");
			return false;
		}
		else if(streamboost_uplink<0.10 || streamboost_uplink>1000.00 || streamboost_downlink<0.10 || streamboost_downlink>1000.00)
		{
			alert("$range_error");
			return false;
		}
		else
		{
			cf.hid_streamboost_uplink.value=parseInt((cf.uplink_value.value)*1000000/8);
			cf.hid_streamboost_downlink.value=parseInt((cf.downlink_value.value)*1000000/8);
		}
		if(first_flag == "0")
			cf.hid_first_flag.value="0";
		else
			cf.hid_first_flag.value="2";
	} else {
		if(cf.uplink_value.value == "")
			cf.hid_streamboost_uplink.value="";
		else if(streamboost_uplink<0.10 || streamboost_uplink>1000.00)
		{
			alert("$range_error");
			return false;
		}
		else
			cf.hid_streamboost_uplink.value=parseInt((cf.uplink_value.value)*1000000/8);

		if(cf.downlink_value.value == "")
			cf.hid_streamboost_downlink.value="";
		else if(streamboost_downlink<0.10 || streamboost_downlink>1000.00)
		{
			alert("$range_error");
			return false;
		}
		else
			cf.hid_streamboost_downlink.value=parseInt((cf.downlink_value.value)*1000000/8);

		if(first_flag == "0")
			cf.hid_first_flag.value="0";
		else
			cf.hid_first_flag.value="2";
	}
	
}	

function check_wmm_apply(cf)
{
	if(cf.wmm_enable.checked == true)
		cf.qos_endis_wmm.value=1;
	else
		cf.qos_endis_wmm.value=0;
	if(cf.wmm_enable_a.checked == true)
		cf.qos_endis_wmm_a.value=1;
	else
		cf.qos_endis_wmm_a.value=0;
}

function check_confirm(cf, url)
{
	cf.hid_bandwidth_type.value=0;
	if(cf.uplink_value.value == "")
		cf.hid_streamboost_uplink.value="";
	else
		cf.hid_streamboost_uplink.value=parseInt((cf.uplink_value.value)*1000000/8);
	if(cf.downlink_value.value == "")
		cf.hid_streamboost_downlink.value="";
	else
		cf.hid_streamboost_downlink.value=parseInt((cf.downlink_value.value)*1000000/8);
	if(cf.detect_database.checked == true)
		cf.hid_detect_database.value=1;
	else
		cf.hid_detect_database.value=0;
	if(cf.help_improve.checked == true)
		cf.hid_improve_service.value=1;
	else
		cf.hid_improve_service.value=0;
	cf.submit_flag.value="apply_streamboost";
	cf.action="/apply.cgi?/" + url + " timestamp=" + ts;
	cf.submit();
}

function check_basic_ookla_speedtest(form)
{
	if(internet_status == "0"){
		alert("$internet_down");
		return false;
	}
	parent.ookla_speedtest_flag = 1;
	form.submit_flag.value="ookla_speedtest";
	form.action="/func.cgi?/QOS_basic.htm timestamp="+ts;
	form.submit();
	return true;
}

function check_ookla_speedtest(form)
{
	if(internet_status == "0"){
		alert("$internet_down");
		return false;
	}
	parent.ookla_speedtest_flag = 1;
	form.submit_flag.value="ookla_speedtest";
	form.action="/func.cgi?/QOS_advanced.htm timestamp="+ts;
	form.submit();
	return true;
}

function check_basic_manual_update(form)
{
	if(internet_status == "0"){
		alert("$internet_down");
		return false;
	}
	form.submit_flag.value="detect_update";
	form.action="/apply.cgi?/QOS_basic.htm timestamp="+ts;
	form.submit();
	return true;
}

function check_manual_update(form)
{
	if(internet_status == "0"){
		alert("$internet_down");
		return false;
	}
	form.submit_flag.value="detect_update";
	form.action="/apply.cgi?/QOS_advanced.htm timestamp="+ts;
	form.submit();
	return true;
}

function device_icon(type_name)
{
	if(type_name >= 1 && type_name <= 51 )
		return "<img src=/image/streamboost/"+type_name+".jpg width=66px height=44px id=icon_img />";
	else
		return "<img src=/image/streamboost/47.jpg width=66px height=44px id=icon_img />";
}

function show_app(cf,mac)
{
	cf.hid_mac.value=mac.toLowerCase();
	cf.submit_flag.value = "show_application";
	cf.action = "/apply.cgi?/QOS_application.htm timestamp="+ts;
	cf.submit();
}

function edit_select_device(cf)
{
	cf.hid_edit_mac.value=parent.qos_edit_mac;
	cf.submit_flag.value = "select_qos_edit";
	cf.action = "/apply.cgi?/QOS_edit_devices.htm timestamp="+ts;
	cf.submit();
}

function select_device(mac,ip,name,priority)
{
	parent.qos_edit_mac=mac;
	parent.qos_edit_ip=ip;
	parent.qos_edit_name=name;
	parent.qos_priority=priority;
	if(top.is_ru_version == 1)
		document.getElementsByName("edit")[0].className="common_bt";
	else
		document.getElementsByName("edit")[0].className="short_common_bt";
	document.getElementsByName("edit")[0].disabled=false;
}

function show_bora(type)
{
	var device_bora="";
	if(type=="Allowed")
		device_bora="$acc_allow";
	else if(type=="Blocked")
		device_bora="$acc_block";
	else
		device_bora="$acc_block";
	return device_bora;
}

function show_icon_name(num)
{
	var device_icon_name="$qos_device47";
	if(num=="1")
		device_icon_name="$qos_device1";
	else if(num=="2")
		device_icon_name="$qos_device2";
	else if(num=="3")
		device_icon_name="$qos_device3";
	else if(num=="4")
		device_icon_name="$qos_device4";
	else if(num=="5")
		device_icon_name="$qos_device5";
	else if(num=="6")
		device_icon_name="$qos_device6";
	else if(num=="7")
		device_icon_name="$qos_device7";
	else if(num=="8")
		device_icon_name="$qos_device8";
	else if(num=="9")
		device_icon_name="$qos_device9";
	else if(num=="10")
		device_icon_name="$qos_device10";
	else if(num=="11")
		device_icon_name="$qos_device11";
	else if(num=="12")
		device_icon_name="$qos_device12";
	else if(num=="13")
		device_icon_name="$qos_device13";
	else if(num=="14")
		device_icon_name="$qos_device14";
	else if(num=="15")
		device_icon_name="$qos_device15";
	else if(num=="16")
		device_icon_name="$qos_device16";
	else if(num=="17")
		device_icon_name="$qos_device17";
	else if(num=="18")
		device_icon_name="$qos_device18";
	else if(num=="19")
		device_icon_name="$qos_device19";
	else if(num=="20")
		device_icon_name="$qos_device20";
	else if(num=="21")
		device_icon_name="$qos_device21";
	else if(num=="22")
		device_icon_name="$qos_device22";
	else if(num=="23")
		device_icon_name="$qos_device23";
	else if(num=="24")
		device_icon_name="$qos_device24";
	else if(num=="25")
		device_icon_name="$qos_device25";
	else if(num=="26")
		device_icon_name="$qos_device26";
	else if(num=="27")
		device_icon_name="$qos_device27";
	else if(num=="28")
		device_icon_name="$qos_device28";
	else if(num=="29")
		device_icon_name="$qos_device29";
	else if(num=="30")
		device_icon_name="$qos_device30";
	else if(num=="31")
		device_icon_name="$qos_device31";
	else if(num=="32")
		device_icon_name="$qos_device32";
	else if(num=="33")
		device_icon_name="$qos_device33";
	else if(num=="34")
		device_icon_name="$qos_device34";
	else if(num=="35")
		device_icon_name="$qos_device35";
	else if(num=="36")
		device_icon_name="$qos_device36";
	else if(num=="37")
		device_icon_name="$qos_device37";
	else if(num=="38")
		device_icon_name="$qos_device38";
	else if(num=="39")
		device_icon_name="$qos_device39";
	else if(num=="40")
		device_icon_name="$qos_device40";
	else if(num=="41")
		device_icon_name="$qos_device41";
	else if(num=="42")
		device_icon_name="$qos_device42";
	else if(num=="43")
		device_icon_name="$qos_device43";
	else if(num=="44")
		device_icon_name="$qos_device44";
	else if(num=="45")
		device_icon_name="$qos_device45";
	else if(num=="46")
		device_icon_name="$qos_device46";
	else if(num=="47")
		device_icon_name="$qos_device47";
	else if(num=="48")
		device_icon_name="$qos_device48";
	else if(num=="49")
		device_icon_name="$qos_device49";
	else if(num=="50")
                device_icon_name="$qos_device50";
	else if(num=="51")
                device_icon_name="$qos_device51";
	else
		device_icon_name="$qos_device47";

	return device_icon_name;
}

function show_type(name)
{
	var device_type="";
	if(name=="wired")
		device_type="$acc_wired";
	else if(name=="primary")
		device_type="2.4G $wireless";
	else if(name=="guest")
		device_type="2.4G $guest_wireless";
	else if(name=="primary_an")
		device_type="5G $wireless";
	else if(name=="guest_an")
		device_type="5G $guest_wireless";
	else if(name=="vpn")
		device_type="$qos_vpn";
	else
		device_type="$acc_wired";
	return device_type;
}

function show_priority(pri)
{
	var device_priority="";
	if(pri=="HIGHEST")
		device_priority="$qos_highest";
	else if(pri=="HIGH")
		device_priority="$qos_high";
	else if(pri=="MEDIUM")
		device_priority="$medium_mark";
	else if(pri=="LOW")
		device_priority="$qos_low";
	else
		device_priority="$medium_mark";

	return device_priority;
}

function show_pri_num(pri)
{
	var device_num="2";
	if(pri=="HIGHEST")
		device_num="4";
	else if(pri=="HIGH")
		device_num="3";
	else if(pri=="MEDIUM")
		device_num="2";
	else if(pri=="LOW")
		device_num="1";
	else
		device_num="2";

	return device_num;
}

function TSorter(num){
        var table = Object;
        var trs = Array;
        var ths = Array;
        var curSortCol = Object;
        var prevSortCol = num;
        var sortType = Object;

        function get(){}

        function getCell(index){
                return trs[index].cells[curSortCol]
        }

        this.init = function(tableName)
        {
                table = document.getElementById(tableName);
                ths = table.getElementsByTagName("th");
                for(var i = 1; i < ths.length ; i++)
                {
                        ths[i].onclick = function()
                        {
                                sort(this);
                        }
                }
                return true;
        };

	this.def_sort = function(tableName, defNum)
	{
		table = document.getElementById(tableName);
		ths = table.getElementsByTagName("th");
		sort(ths[defNum]);
		return true;
	};

        function sort(oTH)
        {
                curSortCol = oTH.cellIndex;
                sortType = oTH.abbr;
                trs = table.tBodies[0].getElementsByTagName("tr");

                setGet(sortType)

                for(var j=0; j<trs.length; j++)
                {
                        if(trs[j].className == 'detail_row')
                        {
                                closeDetails(j+2);
                        }
                }

                if(prevSortCol == curSortCol)
                {
                        oTH.className = (oTH.className != 'descend' ? 'descend' : 'ascend' );
			reverseTable();
                }
                else
                {
                        oTH.className = 'descend';
                        if(ths[prevSortCol].className != 'exc_cell'){ths[prevSortCol].className = '';}
                        quicksort(0, trs.length);
                }
                prevSortCol = curSortCol;
        }

        function setGet(sortType)
        {
                switch(sortType)
                {
                        case "float_text":
                                get = function(index){
                                        return parseFloat(getCell(index).firstChild.value);
                                };
                                break;
                        case "str_text":
                                get = function(index){
                                        return getCell(index).firstChild.value;
                                };
                                break;
                        case "ip_text":
                                get = function(index) {
                                        var value = getCell(index).firstChild.nodeValue;
                                        var each_info = value.split(".");
                                        split_part = parseInt(each_info[0]) + parseInt(each_info[1]) + parseInt(each_info[2]) + parseInt(each_info[3], 10);
                                        return parseInt(split_part);
                                }
                                break;
                        default:
                                get = function(index){  return getCell(index).firstChild.nodeValue;};
                                break;
                };
        }

	function exchange(i, j)
        {
                if(i == j+1) {
                        table.tBodies[0].insertBefore(trs[i], trs[j]);
                } else if(j == i+1) {
                        table.tBodies[0].insertBefore(trs[j], trs[i]);
                } else {
                        var tmpNode = table.tBodies[0].replaceChild(trs[i], trs[j]);
                        if(typeof(trs[i]) == "undefined") {
                                table.appendChild(tmpNode);
                        } else {
                                table.tBodies[0].insertBefore(tmpNode, trs[i]);
                        }
                }
        }

        function reverseTable()
        {
                for(var i = 1; i<trs.length; i++)
                {
                        table.tBodies[0].insertBefore(trs[i], trs[0]);
                }
        }

	function quicksort(lo, hi)
        {
                if(hi <= lo+1) return;

                if((hi - lo) == 2) {
                        if(get(hi-1) > get(lo)) exchange(hi-1, lo);
                        return;
                }

                var i = lo + 1;
                var j = hi - 1;

                if(get(lo) > get(i)) exchange(i, lo);
                if(get(j) > get(lo)) exchange(lo, j);
                if(get(lo) > get(i)) exchange(i, lo);

                var pivot = get(lo);

                while(true) {
                        j--;
                        while(pivot > get(j)) j--;
                        i++;
                        while(get(i) > pivot) i++;
                        if(j <= i) break;
                        exchange(i, j);
                }
                exchange(lo, j);

                if((j-lo) < (hi-j)) {
                        quicksort(lo, j);
                        quicksort(j+1, hi);
                } else {
                        quicksort(j+1, hi);
                        quicksort(lo, j);
                }
        }
}

function show_or_hid_refresh(cf, tag)
{
	if(tag == 0)
	{
		if(cf.enable_auto_refresh.checked)
			cf.hid_dev_auto_refresh.value = "1";
		else	
			cf.hid_dev_auto_refresh.value="0";
			
		cf.action="/apply.cgi?/QOS_show_device.htm timestamp="+ts;
		cf.submit_flag.value="auto_refresh_value";
		cf.submit();
	}
	else
	{
		if(cf.enable_auto_refresh.checked)
			cf.hid_ap_auto_refresh.value = "1";
		else
			cf.hid_ap_auto_refresh.value="0";

		cf.submit();
	}
}
