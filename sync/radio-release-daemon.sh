#! /bin/sh

### BEGIN INIT INFO
# Provides:             Marvell
# Default-Start:        2 3 4 5
# Default-Stop:         
# Short-Description:    Start release check script when server startup
### END INIT INFO

SCRIPT_DIR=/home/manson/OTA/scripts
CMD="/home/manson/OTA/scripts/sync_cp.sh"
PID=/var/run/radio-release-daemon.pid
USER=manson

. /lib/lsb/init-functions

case "$1" in
  start)
        log_daemon_msg "Starting marvell radio release check script" "radio-release-daemon"
        if start-stop-daemon -c $USER --start --quiet --oknodo -v -d $SCRIPT_DIR -m -b --pidfile $PID --exec $CMD -- ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
        ;;
  stop)
        log_daemon_msg "Stopping marvell radio release check script" "radio-release-daemon"
        if start-stop-daemon -c $USER --stop --quiet --oknodo --pidfile $PID; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
        ;;

  *)
        log_action_msg "Usage: /etc/init.d/radio-release-daemon {start|stop}"
        exit 1
esac

exit 0
