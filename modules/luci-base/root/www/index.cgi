#!/bin/sh
. /lib/functions/network.sh
network_get_ipaddr ipaddr lan

case $HTTP_HOST in
    $(uname -n)|*.lan|adb.pcwrt.com)
	ipaddr=$HTTP_HOST
	;;
    *)
	;;
esac

echo "Status: 302 Found"                     
echo "Location: http://$ipaddr/cgi-bin/pcwrt"
echo "Content-Type: text/html; charset=UTF-8"
echo "Content-Length: 0"
echo                                         
      
exit 0
