#!/bin/bash
set -e

trap stop_gracefully TERM INT

stop_gracefully(){
  echo "stopping ampd process"
  killall "ampd"
  sleep 5
  echo "ampd process stopped"
}

/usr/local/bin/ampd &
wait
exec "$@"