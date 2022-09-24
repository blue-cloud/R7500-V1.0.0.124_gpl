start_RtDebugMode()
{
	mkdir /dev/pts
	mknod -m 666 /dev/ptmx c 5 2
	mknod -m 666 /dev/pts/0 c 136 0
	mknod -m 666 /dev/pts/1 c 136 1

	killall utelnetd
	killall telnetenable

	if [ "x$(/bin/config get factory_mode)" = "x1" ]; then
		/usr/sbin/utelnetd -d -i br0
		/bin/config set disable_telnet_login=1
	else
		/usr/sbin/telnetenable
	fi
}
