#!/bin/sh

DIR=/var/log/aviatrix
if [ ! -d ${DIR} ]; then exit 1; fi
DESTDIR=s3://mybucket

current_time=$(date +%Y-%m-%dT%H-%M-%S)
new_filename=gateways.${current_time}.log

# rename the file
if [ -f ${DIR}/gateways.log ]; then
    sudo mv ${DIR}/gateways.log ${DIR}/${new_filename}
    if [ $? -ne 0 ]; then exit 2; fi

    # HUP rsyslogd to start logging to new file
    sudo killall -HUP rsyslogd
    if [ $? -ne 0 ]; then exit 3; fi
fi

# copy any outstanding file(s) to s3 bucket
cd ${DIR}
for f in $(ls); do
  if [ "$f" != "gateways.log" ]; then
      aws s3 cp ${DIR}/$f ${DESTDIR}/${new_filename}
      if [ $? -eq 0 ]; then
          sudo rm -f ${DIR}/$f
      fi
  fi
done
