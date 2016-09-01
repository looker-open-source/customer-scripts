#!/bin/bash
# inotifysync.sh
# requires inotify-tools package
#
# needs to be a little less noisy when the process is not running and you
# try to stop or start

WATCHDIR=/home/looker/looker/models
# space seperated server names or ips in quotes
SYNCDEST="10.0.0.1 10.0.0.2"

EVENTS="CREATE,DELETE,MODIFY,MOVED_FROM,MOVED_TO"

PIDFILE=~/.inotifysync.pid

sync() {
  for DEST in $SYNCDEST ; do
    rsync --update --delete -alqr ${WATCHDIR}/ ${DEST}:$WATCHDIR
  done
}
watch() {
  inotifywait -q -e "$EVENTS" -m -r --format '%:e %f' $WATCHDIR
}

watchloop() {
  watch | (
  while true ; do
    read -t 5 LINE && sync
  done
  )
}

killtree() {
    local _pid=$1
    local _sig=${2:-9}
    kill -stop ${_pid} > /dev/null 2>&1  # needed to stop quickly forking parent from producing children between child killing and parent killing
    for _child in $(ps -o pid --no-headers --ppid ${_pid}); do
        killtree ${_child} ${_sig}
    done
    kill -${_sig} ${_pid} > /dev/null 2>&1 
}

start() {
    if [ -e ${PIDFILE} ] && kill -0 `cat ${PIDFILE}` > /dev/null 2>&1  ; then
        echo "inotifysync is already running"
        exit 1
    fi

    # make sure the lockfile is removed when we exit and then claim it
    trap "rm -f ${PIDFILE} ; killtree $$ ; exit" INT TERM EXIT
    echo $$ > ${PIDFILE}

  # make sure we start with synced directories
  sync
  watchloop
}

stop() {
  if [ -e ${PIDFILE} ] && kill -0 `cat ${PIDFILE}` > /dev/null 2>&1  ; then
    killtree `cat ${PIDFILE}`
    kill `cat ${PIDFILE}` > /dev/null 2>&1 
    if kill -0 `cat ${PIDFILE}` > /dev/null 2>&1  ; then
      kill -9 `cat ${PIDFILE}`
    fi
    echo 'inotifysync stopped'
  else
    echo 'inotifysync not running'
  fi
}

case "$1" in
  startbg)
    start
    ;;
  start)
    if [ -e ${PIDFILE} ] && kill -0 `cat ${PIDFILE}` > /dev/null 2>&1  ; then
      echo "inotifysync is already running"
      exit 1
    else
      $0 startbg > /dev/null 2>&1  &
    fi
    ;;
  stop)
    stop
    ;;
  restart)
    echo "Restarting Looker inotify script" "looker"
    stop
    sleep 3
    start
    ;;
  status)
    if [ -e ${PIDFILE} ] && kill -0 `cat ${PIDFILE}` > /dev/null 2>&1  ; then
      echo "Status:inotifysync running"
      exit 0
    fi
    ;;
  *)
    echo "USAGE: $0 (start|stop|restart|status)"
    ;;
esac

