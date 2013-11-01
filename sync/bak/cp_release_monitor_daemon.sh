#! /bin/sh

CMD=$GOBIN/monitor
PID=/var/run/cp_release_monitor_daemon.pid

. /lib/lsb/init-functions

case "$1" in
  start)
        log_daemon_msg "Starting marvell cp release monitor" "cp_release_monitor_daemon"
        if start-stop-daemon -c $USER --start --quiet --oknodo -m --pidfile $PID --exec $CMD -- ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
        ;;
  stop)
        log_daemon_msg "Stopping marvell cp release monitor" "cp_release_monitor_daemon"
        if start-stop-daemon -c $USER --stop --quiet --oknodo -m --pidfile $PID; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
        ;;

  *)
        log_action_msg "Usage: /etc/init.d/cp_release_monitor_daemon {start|stop}"
        exit 1
esac

exit 0
