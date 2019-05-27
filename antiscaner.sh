#!/bin/bash
APPNAME=antiscaner.sh
TMP_DIR=/tmp
TMP_LIST=$TMP_DIR/tmp_list.log
IP_LIST=$TMP_DIR/ip_list.log
LOGFILE="/var/log/iptables.log"
IPTABLES_SIGN="IPTABLES"

### Show help ###
help()
{
  echo "help"
}

### Reset to the defalt options ###
reset()
{
  ### Reset defalt policies 
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  ### Delete chains
  iptables -t nat -F
  iptables -t nat -X
  iptables -t mangle -F
  iptables -t mangle -X
  iptables -F
  iptables -X
}

### Set logfile
set_logfile()
{
  local log_config_file="/etc/rsyslog.d/iptables.conf"
  echo ':msg, contains, "'$IPTABLES_SIGN'" -'$LOGFILE > $log_config_file
  echo '& ~' >> $log_config_file
  /etc/init.d/rsyslog restart
}

log_rotate()
{
  echo "/var/log/iptables.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    sharedscripts
 }" > /etc/logrotate.d/iptables
}

set_rules()
{
  iptables -N antiscan
  iptables -A antiscan -j LOG --log-prefix "$IPTABLES_SIGN"
  iptables -A antiscan -j RETURN

  iptables -A INPUT -i lo -j ACCEPT
  
  iptables -A INPUT -p udp --dport 53 -j ACCEPT
  
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -m recent --rcheck --seconds 3600 --hitcount 10 --rttl -j antiscan
  iptables -A INPUT -m recent --rcheck --seconds 60 --hitcount 2 --rttl -j antiscan
  iptables -A INPUT -m recent --set
 
  iptables -P INPUT DROP
}

create_task()
{
  task=$(pwd)/$APPNAME
  (crontab -l; echo "* * * * * "$task" -p") 2> /dev/null | sort | uniq | crontab -
}

TMP_LIST=tmp_list.log
IP_LIST=ip_list.log

send_notify()
{
    #Detect the name of the display in use
    local display=":$(ls /tmp/.X11-unix/* | sed 's#/tmp/.X11-unix/X##' | head -n 1)"

    #Detect the user using such display
    local user=$(who | grep '('$display')' | awk '{print $1}')

    #Detect the id of the user
    local uid=$(id -u $user)

    sudo -u $user DISPLAY=$display DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus notify-send "$@"
}

### Parse log-file ###
parse_log()
{
  if [ ! -f "$IP_LIST" ]; then
    touch $IP_LIST
  fi
  #grep $IPTABLES_SIGN $LOGFILE
  grep -E -o "SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}" $LOGFILE |\
  grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq > $TMP_LIST

  new_ip=$(diff -wB $TMP_LIST $IP_LIST | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" )
  if [ -n "$new_ip" ] ; then
    notify "${new_ip[*]}"
    echo "$new_ip" >> $IP_LIST
  fi
  local iptmp=$TMP_DIR/ip.tmp
  cat $IP_LIST | sort > $iptmp
  mv $iptmp $IP_LIST
}

notify()
{
  ip_list=("$@")
  for ip in $ip_list
  do
     echo "Your computer was scanned by ip: $ip !"
     send_notify "Your computer was scanned by ip: $ip !"
    ##email
  done
}


### Main ###
IS_SUDO=$(id -u)
if [ $IS_SUDO -ne 0 ] ; then
  echo "You need to run this script as root!"
  exit 0
else
  echo "OK"
fi

while [ -n "$1" ]
do
  case "$1" in
	-o)
		set_logfile
		log_rotate
		;;
	-c)
	    create_task
	    ;;
        -h | --help )
            help
       	    ;;
	-r | --reset)
	    reset
	    ;;
	-p)
	    parse_log
	    ;;
	-s)
	    set_rules
	    ;;
#-b) echo "Found the -b option" ;;
#-c) echo "Found the -c option" ;;
        *) 
            echo "Error: bad argument. Use '-h' option to get help" ;;
    esac
    shift
done
