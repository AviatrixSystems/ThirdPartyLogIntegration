# Overview

This directory contains the Aviatrix Controller syslog integration for Datadog.

## How this script works

The script runs in the background listening for connections from [rsyslog omuxsock output module](https://www.rsyslog.com/doc/v8-stable/configuration/modules/omuxsock.html).  When configured in rsyslog, it will send messages to this script for processing.  Each message is processed according to the configuration in the script where the message is either converted into a metric or ignored.  The metrics are sent to Datadog using the Datadog API (this requires a new API key to work).

# Installation

1. Create a new [API key](https://app.datadoghq.com/account/settings#api)
2. Open the Python script file and modify the `DDOG_OPTIONS` dictionary with the new API key in `api_key`
3. Create `/etc/rsyslog.d/xx-metrics.conf` (where `xx` is any number used to prioritize the order of this configuration relative to others in the directory)
4. Copy the script to `/etc/cloud/`

5. Run the following commands to prepare the script to run:
``` bash
sudo chomd +x /etc/cloud/avx_datadog_metrics_writer.py
sudo pip install datadog python-dateutil
```

6. Create a configuration for this script to run in background and save it in `/etc/init` (e.g., `/etc/init/avx-datadog-metrics-writer.conf`)

``` configuration
description "Parser for Aviatrix* rsyslogd messages to be converted to Datadog metrics/events"
    author  "Aviatrix Support <support@aviatrix.com>"

    start on runlevel [234]
    stop on runlevel [0156]

    chdir /tmp
    exec /etc/cloud/avx_datadog_metrics_writer.py
    respawn
```


7. Run the following commands to set up the scrip to run automatically and in background.
``` bash
sudo initctl reload-configuration
sudo start avtx-datadog-metrics-writer
```

8. Create rsyslog configuration in `/etc/rsyslog.d/` (e.g., `/etc/rsyslog.d/22-avx-datadog-metrics-writer.conf`):

``` configuration
# load the socket output module that we'll use to send messages
# to the datadog writer
$ModLoad omuxsock
$OMUxSockSocket /tmp/avx-datadog-metrics-writer.socket

# define the template for messages written to the datadog writer
# time reported<TAB>message<NEWLINE>
template(name="aviatrixwriterformat" type="list") {
        property(name="timereported")
        constant(value="\t")
        property(name="msg")
        constant(value="\n")
}

# write messages to the socket when they match the messages below
if (($msg contains 'AviatrixTunnelStatusChange') or ($msg contains 'AviatrixGwNetStats') or ($msg contains 'AviatrixGwSysStats')) then {
  :omuxsock:;aviatrixwriterformat
}
```

