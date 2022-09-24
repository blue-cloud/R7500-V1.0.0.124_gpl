#!/bin/sh

cmd=$1
ret=0

usage()
{
	echo "Usage:"
	echo "	repeater.sh {create_ap_intf | destroy_ap_intf} [interface name]"
	echo ""
}

if [ $# -eq 2 ]
then
	repeater_ap_intf=$2
elif [ $# -eq 1 ]
then
	ret=$(call_qcsapi -u -q get_ap_interface_name)
	if [ $? -eq 0 ]; then
		repeater_ap_intf=$ret
	else
		echo "Failed to get AP interface name" >&2
		exit 1
	fi
else
	usage
	exit 1
fi

create_repeater_ap()
{
	ret=0

	ifconfig $repeater_ap_intf 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "start 0 ap $repeater_ap_intf" >/sys/devices/qdrv/control
		ret=$?
	fi

	return $ret
}

destroy_repeater_ap()
{
	ret=0

	ifconfig $repeater_ap_intf 2>/dev/null
	if [ $? -eq 0 ]; then
		ifconfig $repeater_ap_intf down
		echo "stop 0 $repeater_ap_intf" >/sys/devices/qdrv/control
		ret=$?
	fi

	return $ret
}

if [ "$cmd" = "create_ap_intf" ]
then
	create_repeater_ap
elif [ "$cmd" = "destroy_ap_intf" ]
then
        destroy_repeater_ap
else
	usage
	ret=1
fi

return $ret
