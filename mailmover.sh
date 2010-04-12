#!/bin/sh

### BEGIN INIT INFO
# Provides:          mailmover
# Should-Start:      $sendmail
# Default-Start:     2 3 4 5
# Default-Stop:      1
# Short-Description: OpenEMM mailmover tool
# Description:       mailmover is a tool that watches OpenEMM's own mail queue
#                    and copies new mails over to the system-wide sendmail mail queue
### END INIT INFO

set -e

# /etc/init.d/mailmover: start and stop the mailmover helper application for OpenEMM

DAEMON=/usr/bin/mailmover
MAILMOVER_OPTS=''

test -x $DAEMON || exit 0

. /lib/lsb/init-functions
. /etc/default/rcS

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin"

case "$1" in
    start)
        log_daemon_msg "Starting mailmover daemon" "mailmover"
        if [ -s /var/run/mailmover.pid ] && kill -0 $(cat /var/run/mailmover.pid) > /dev/null 2>&1; then
            log_progress_msg "apparently already running"
            log_end_msg 0
        exit 0
        fi
        
        if start-stop-daemon --start --quiet --background \
            --pidfile /var/run/mailmover.pid --make-pidfile \
            --exec /usr/bin/mailmover
        then
            rc=0
            sleep 1
            if ! kill -0 $(cat /var/run/mailmover.pid) > /dev/null 2>&1; then
                log_failure_msg "mailmover daemon failed to start"
                rc=1
            fi
        else
            rc=1
        fi
        if [ $rc -eq 0 ]; then
            log_end_msg 0
        else
            log_end_msg 1
            rm -f /var/run/mailmover.pid
        fi
    ;;
    stop)
        log_daemon_msg "Stopping mailmover daemon" "mailmover"
        start-stop-daemon --stop --quiet -oknodo --pidfile /var/run/mailmover.pid
        log_end_msg $?
        rm -f /var/run/mailmover.pid
    ;;
    restart)
        set +e
        log_daemon_msg "Restarting mailmover daemon" "mailmover"
        if [ -s /var/run/mailmover.pid ] && kill -0 $(cat /var/run/mailmover.pid) > /dev/null 2>&1; then
            start-stop-daemon --stop --quiet --pidfile /var/run/mailmover.pid --exec /usr/bin/mailmover || true
            sleep 1
        else
            log_warning_msg "mailmover daemon not running, attempting to start."
            rm -f /var/run/mailmover.pid
        fi
        if start-stop-daemon --start --quiet --background \
            --pidfile /var/run/mailmover.pid --make-pidfile  --exec /usr/bin/mailmover
        then
            rc=0
            sleep 1
            if ! kill -0 $(cat /var/run/mailmover.pid) > /dev/null 2>&1; then
                log_failure_msg "mailmover daemon failed to start"
                rc=1
            fi
        else
            rc=1
        fi
    ;;
    status)
        status_of_proc -p /var/run/mailmover.pid "$DAEMON" mailmover && exit 0 || exit $?
    ;;
    *)
        echo "Usage: /etc/init.d/mailmover {start|stop|restart|status}"
        exit 1
esac

exit 0
