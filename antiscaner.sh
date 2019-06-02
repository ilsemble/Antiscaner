#!/bin/bash
APPNAME=antiscaner.sh
TMP_DIR=/tmp
TMP_LIST=$TMP_DIR/tmp_list.log
IP_LIST=$TMP_DIR/ip_list.log
LOGFILE="/var/log/iptables.log"
OLD_CONFIG="/etc/firewall_old.conf"
CONFIG="/etc/firewall.conf"
CONFIG_RESTORER="/etc/network/if-up.d/00-iptables"
IPTABLES_SIGN="IPTABLES"
TASK=$(pwd)/$APPNAME


### Show help ###
help()
{
  echo "This scripts provides ports scanning protections."
  echo "It uses Iptables as the foundation."
  echo "Usage:"
  echo "-h, --help       Print this manual."
  echo "-i, --install    Install all components."
  echo "-s, --start      Start protection from ports scanning."
  echo "-u, --uninstall  Remove all and stop protection."    
  echo "Also you need to run this script as root!"
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
  (crontab -l; echo "* * * * * "$TASK" -p") 2> /dev/null | sort | uniq | crontab -
}

delete_task()
{
  crontab -l | grep -v "$TASK" 2> /dev/null | crontab -
}


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
  grep -E -o "SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}" $LOGFILE |\
  grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq > $TMP_LIST

  local new_ip=$(diff -wB $TMP_LIST $IP_LIST | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" )
  if [ -n "$new_ip" ] ; then
    notify "${new_ip[*]}"
  fi
  mv $TMP_LIST $IP_LIST
}

notify()
{
  ip_list=("$@")
  mail=$(grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" /etc/ssmtp/ssmtp.conf)
  echo "Your computer was scanned by ip:\n $ip_list !"
  send_notify "Your computer was scanned by ip: $ip_list !"
  local mail_text=$TMP_DIR/mail.tmp
  echo "Subject: Antiscaner" > $mail_text
  echo "" >> $mail_text
  echo "Your computer was scanned by ip:" >> $mail_text
  echo "$ip_list" >> $mail_text
  sendmail -v $mail < $mail_text
  rm -f $mail_text
}

install()
{
  ### Install ssmtp to send email
  apt-get install ssmtp
  echo "\n\nYou need to configure ssmtp-server to get email notification!"
  echo "Fill in the files /etc/ssmtp/ssmtp.conf and /etc/ssmtp/revaliases\n" 

  ##Configure log of Iptables and log rotation.
  set_logfile
  log_rotate
  
  iptables-save > $OLD_CONFIG
}

uninstall()
{
  delete_task
  rm -f $CONFIG_RESTORER
  rm -f $CONFIG
  reset
  
  iptables-restore < $OLD_CONFIG
  
  rm -f $IP_LIST
}

start_protection()
{ 
  if [ ! -f "$LOGFILE" ]; then
    echo "You need to install this program first!"
    exit 1
  fi
   
  reset
  set_rules

  iptables-save > $CONFIG

  echo "#!/bin/sh" > $CONFIG_RESTORER
  echo "iptables-restore < $CONFIG" >> $CONFIG_RESTORER
  chmod +x $CONFIG_RESTORER  
  
  create_task
}


### Check user to have the root privilegies ###
### @retval 0 if user has root privilegies
###         1 if not
check_is_sudo()
{
  IS_SUDO=$(id -u)
  if [ $IS_SUDO -ne 0 ] ; then
    echo "You need to run this script as root!"
    exit 0
  fi
}


### Main ###
while [ -n "$1" ]
do
  case "$1" in
    -h | --help )
      help
      ;;
    -i | --install )
      check_is_sudo
      install
      ;;
    -p )
      parse_log
      ;;
    -s | --start )
      check_is_sudo
      start_protection
      ;;
     -u | --uninstall)
      check_is_sudo
      uninstall
      ;;       
     * ) 
      echo "Error: bad argument. Use '-h' option to get help"
      ;;
    esac
  shift
done
