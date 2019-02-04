#!/bin/bash

set -e

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BASEDIR=$(realpath "${SCRIPT_DIR}/..")
ONLYBUILD=0
DEVEL=0
usage="$(basename $0) [-h] [-b] [-d]

where:
    -h    This help.
    -b    Build the image and exit. You need to build the image before running it.
    -d    Run in development mode: mount directory directly.

With no flags, it runs the default mode."

build_image() {
  cd $SCRIPT_DIR/..
  docker build -t web_scion -f $SCRIPT_DIR/Dockerfile .
}
run_image() {
  docker run -p 127.0.0.1:8000:8000 -it web_scion
}
run_image_devel() {
  docker run -v "${BASEDIR}:/home/scion/go/src/github.com/netsec-ethz/scion-web" -p 127.0.0.1:8000:8000 -it web_scion 
}

while getopts "hbd" opt; do
  case $opt in
    h)
      echo "$usage"
      exit 0
      ;;
    b)
      ONLYBUILD=1
      ;;
    d)
      DEVEL=1
      ;;
    \?)
      echo "Invalid option"
      echo "$usage" >&2
      exit 1
      ;;
  esac
done

if ! ( [ $(id -u) -eq 0 ] || groups | grep -q "\<docker\>"; ); then
    echo "Error: you must either be root, or in the 'docker' group"
    exit 1
fi

if [ $ONLYBUILD -eq 1 ]; then
  echo "Building docker image"
  build_image
  exit 0
fi

if [ $DEVEL -eq 1 ]; then
  echo "Running in development mode"
  run_image_devel
else
  echo "Running in normal mode"
  run_image
fi
