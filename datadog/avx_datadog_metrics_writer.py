#! /usr/bin/python
"""
This script should be used as an endpoint for a rsyslogd configured with
the omuxsock output module.
"""

import datetime
import json
import os
import os.path
import socket
import threading

import datadog
import datadog.api
import datadog.api.constants
import dateutil
import dateutil.parser
import requests

PORT = 10514
DDOG_OPTIONS = {
    'api_key': 'YOUR KEY HERE'
}

# MESSAGES dict contains configuration used by the parsing logic below.
# the key is the aviatrix syslog message type (parsed out from the first
# word of the syslog message)
# 'processor' should point to a function in this file that will handle the
#             processing of the message (after parse).  The function signature
#             should look like:
#             __processor_name__(config, reported_date, attrs)
#             where:
#               config - dict config for this message type (e.g., the object
#                        pointed to by 'AviatrixTunnelStatusChange')
#               reported_date - datetime object parsed from syslog date/time
#               attrs - dict of token name -> value parsed using the 'tokens'
#                       configuration for this message type
# 'tokens' a dictionary defining the expected token keys in the message.
#          the value is another dictionary representing configuration for
#          this token.  Accepted configuration keys:
#            required : True/False : Is this token required to be in message?
#            ignore : True/False : Skip and don't use this key/value?
#            is_timestamp: True/False : is the value for this token the
#                          timestamp for the metric/event
#            is_hostname: True/False : is the value for this token the
#                         host for this metric/event
#            is_numeric: True/False: if True, characters not matching [0-9.-]
#                        will be removed before value is stored
#            is_bytes: True/False: if True, parses the value for "kb", "mb",
#                      "gb" and converts the value to kb
#            name: string : the metric/event name (instead of the token name)
#            name_variable: string: the value of this configuration is the
#                           variable that appears in the prefix.  replace
#                           this variable (contained in the prefix) with
#                           the value of the token.
# 'metric' either 'None' for events or a dict for metrics.  The dict contains
#          configuration items for metrics.  Accepted values:
#             prefix: the metric name prefix (can contain variables; see above)
MESSAGES = {
    'AviatrixTunnelStatusChange': {
        'processor': 'process_tunnel_change',
        'tokens': {
            'src_gw': {
                'required': True
            },
            'dst_gw': {
                'required': True
            },
            'old_state': {
                'required': True
            },
            'new_state': {
                'required': True
            },
            'legacy': {
                'required': False
            }
        },
        'metric': None
    },
    'AviatrixGwSysStats': {
        'processor': 'process_metrics',
        'tokens': {
            'timestamp': {
                'required': True,
                'is_timestamp': True
            },
            'name': {
                'required': True,
                'is_hostname': True
            },
            'cpu_idle': {
                'required': True,
                'name': 'cpu.idle.percent',
                'is_numeric': True
            },
            'memory_free': {
                'required': True,
                'name': 'memory.free.kb',
                'is_numeric': True
            },
            'disk_total': {
                'required': True,
                'name': 'disk.total.kb',
                'is_numeric': True
            },
            'disk_free': {
                'required': True,
                'name': 'disk.free.kb',
                'is_bytes': True
            }
        },
        'metric': {
            'prefix': 'aviatrix.gateway.'
        }
    },
    'AviatrixGwNetStats': {
        'processor': 'process_metrics',
        'tokens': {
            'timestamp': {
                'required': True,
                'is_timestamp': True
            },
            'name': {
                'required': True,
                'is_hostname': True
            },
            'public_ip': {
                'required': False,
                'ignore': True
            },
            'private_ip': {
                'required': False,
                'ignore': True
            },
            'interface': {
                'required': True,
                'name_variable': '%interface%'
            },
            'total_rx_rate': {
                'required': True,
                'name': 'rx.rate.total.kb',
                'is_bytes': True
            },
            'total_tx_rate': {
                'required': True,
                'name': 'tx.rate.total.kb',
                'is_bytes': True
            },
            'total_rx_tx_rate': {
                'required': True,
                'name': 'rxtx.rate.total.kb',
                'is_bytes': True
            }
        },
        'metric': {
            'prefix': 'aviatrix.gateway.%interface%.'
        }
    },
    'AviatrixLicsenseVPNUsers': {
        'processor': 'process_metrics',
        'tokens': {
            'users': {
                'required': True,
                'is_numeric': True,
                'name': 'users.active'
            }
        },
        'metric': {
            'prefix': 'aviatrix.vpn.'
        }
    },
    'AviatrixVPNSession': {
        'processor': 'process_vpn_session',
        'tokens': {
            'User': {
                'required': True,
                'is_tag': True
            },
            'Status': {
                'required': True
            },
            'Gateway': {
                'required': True,
                'is_hostname': True
            },
            'VPNVirtualIP': {
                'required': True,
                'is_tag': True
            },
            'PublicIP': {
                'required': False,
                'is_tag': False
            },
            'GatewayIP': {
                'required': False,
                'is_tag': False
            },
            'Login': {
                'required': True,
                'is_tag': True
            },
            'Logout': {
                'required': True,
                'is_tag': True
            },
            'Duration': {
                'required': True,
                'is_tag': True
            },
            'RXbytes': {
                'required': True,
                'is_bytes': True,
                'name': 'tx.total.kb',
                'is_tag': True
            },
            'TXbytes': {
                'required': True,
                'is_bytes': True,
                'name': 'tx.total.kb',
                'is_tag': True
            }
        },
        'metric': None
    }
}


def opensocket(port):
    """
    Opens the socket and returns the file descriptor

    Arguments:
    port - the port to listen on

    Returns:
    socket file descriptor
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', port))
    sock.listen(5)
    return sock

EPOCH = datetime.datetime.utcfromtimestamp(0)
def unix_time(date_to_convert):
    """
    Converts the given datetime object to unix time (seconds since epoch)
    """
    if not date_to_convert:
        return 0
    return long((date_to_convert - EPOCH).total_seconds())

def process_tunnel_change(config, reported_date, attrs):
    """
    Processes a AviatrixTunnelStatusChange message.
    Arguments:
    config - the configuration from MESSAGES
    reported_date - the datetime object representing when this event occurred
    msg - the syslog message.  Example (with line breaks added here):
       src_gw=Oregon-DevOps-VPC(AWS us-west-2)
       dst_gw=gcloud-prod-vpc(Gcloud us-central1)
       old_state=Down
       new_state=Up
    """

    tags = ['aviatrix:tunnel_status_change']
    for key, value in attrs.iteritems():
        if key[-6:] == '_state':
            # there is a bug in 2.7 where the value is a json object
            attrs[key] = parse_state_from_value(value)
        else:
            attrs[key] = value
        # datadog tags
        tags.append(key + ':' + attrs[key])

    text = ('The tunnel between %s and %s is now %s (previously %s)' %
            (attrs['src_gw'], attrs['dst_gw'], attrs['new_state'].upper(),
             attrs['old_state'].upper()))
    title = 'Tunnel is %s' % (attrs['new_state']).upper()
    alert_type = 'error' if attrs['new_state'] == 'Down' else 'success'

    # parse out the host name (drop the ()'s)
    host = attrs['src_gw']
    paren_loc = attrs['src_gw'].find('(')
    if paren_loc > -1:
        host = host[0:paren_loc]

    # send the event to datadog
    datadog.api.Event.create(title=title,
                             text=text,
                             tags=tags,
                             alert_type=alert_type,
                             source_type_name='Aviatrix',
                             date_happened=unix_time(reported_date),
                             host=host)

def process_vpn_session(config, reported_date, attrs):
    """
    Processes the AviatrixVPNSession message.
    """

    tags = ['aviatrix:vpn_session']
    for key, value in attrs.iteritems():
        token_config = config['tokens'][key]
        if 'is_tag' in token_config and token_config['is_tag']:
            tag_value = parse_value(token_config, value)
            if 'name' in token_config:
                tags.append(token_config['name'] + ':' + tag_value)
            else:
                tags.append(key + ':' + tag_value)

    # get hostname
    host = attrs['Gateway']

    # status
    status = attrs['Status']

    # get the start time
    if status == 'active':
        title = 'User connected to VPN'
        text = '%s connected to %s at %s' % (attrs['User'], attrs['Gateway'], attrs['Login'])
        reported_date = dateutil.parser.parse(attrs['Login'])
    else:
        title = 'User disconnected from VPN'
        text = '%s disconnected from %s at %s' % (attrs['User'], attrs['Gateway'], attrs['Logout'])
        reported_date = dateutil.parser.parse(attrs['Logout'])

    datadog.api.Event.create(title=title,
                             text=text,
                             tags=tags,
                             alert_type='info',
                             source_type_name='Aviatrix',
                             date_happened=unix_time(reported_date),
                             host=host)

def process_metrics(config, reported_date, attrs):
    """
    Processes a generic message that contains attributes with keys and values.
    Example:
       AviatrixGwSysStats: timestamp=2017-10-26 21:26:05.241227
                           name=gw-aws-east
                           cpu_idle=100
                           memory_free=241588
                           disk_total=8115168
                           disk_free=4829980
    """

    # if the config indicates this is not a metric, then just return
    if not 'metric' in config or not config['metric']:
        return

    prefix = config['metric']['prefix']
    metrics = {}
    name_vars = {}
    hostname = 'N/A'

    # loop over all attributes found when parsing the tokens in process()
    for key, value in attrs.iteritems():
        token_config = config['tokens'][key]
        if 'is_hostname' in token_config and token_config['is_hostname']:
            hostname = value
        elif 'is_timestamp' in token_config and token_config['is_timestamp']:
            reported_date = dateutil.parser.parse(value)
        elif 'ignore' in token_config and token_config['ignore']:
            continue
        elif 'name_variable' in token_config:
            name_vars[token_config['name_variable']] = value
        else:
            # the default metric name is the value of the attribute/token name
            # with the '_' characters replaced with '.'.
            # unless the config defines a 'name' and then use that
            if 'name' in token_config:
                name = token_config['name']
            else:
                name = key.replace('_', '.')

            metrics[name] = parse_value(token_config, value)
    for search, value in name_vars.iteritems():
        prefix = prefix.replace(search, value)

    for key, value in metrics.iteritems():
#        print 'Sending %s = %s' % (prefix + key, str(value))
        datadog.api.Metric.send(metric=prefix + key,
                                points=[(unix_time(reported_date), value)],
                                host=hostname,
                                type='gauge')

def parse_value(token_config, value):
    """
    Parses the value provided using the configuration specified in token_config
    Arguments:
    token_config - dictonary with configuration for this token
    value - the value found for this token
    Returns:
    parsed/processed/clean value (or original value if none needed)
    """

    # clean up the value if needed
    if 'is_numeric' in token_config and token_config['is_numeric']:
        # include chars that are numeric including '.' and '-'
        return ''.join(char for char in value if char.isdigit() or char == '.' or char == '-')
    elif 'is_bytes' in token_config and token_config['is_bytes']:
        numeric_val = ''
        non_numeric_val = ''
        for char in value:
            if char.isdigit() or char == '.' or char == '-':
                numeric_val = numeric_val + char
            elif not char.isspace():
                non_numeric_val = non_numeric_val + char
        non_numeric_val = non_numeric_val.lower()
        if non_numeric_val == 'kb':
            return numeric_val
        elif non_numeric_val == 'mb':
            return str(float(numeric_val) * 1000)
        elif non_numeric_val == 'gb':
            return str(float(numeric_val) * 1000 * 1000)
        else:
            return numeric_val
    else:
        return value

def parse_tokens_from_string(config, msg):
    """
    Parses out tokens and values from the given string in the format:
    abc=foo def=bar ...

    Arguments:
    config - the configuration from MESSAGES for this msg_type
    msg - the string to parse

    Returns:
    dictionary of token name to value (example: {'abc': 'foo', 'def': 'bar' ... })
    """

    locations = {}
    for token, token_config in config['tokens'].iteritems():
        token = token + '='
        location = msg.find(token)
        if location == -1:
            if token_config['required']:
                return None
        else:
            locations[location] = token

    # go through the tokens found in reverse order they were found in the string
    prev_loc = None
    attrs = {}
    for loc in reversed(sorted(locations.iterkeys())):
        token = locations[loc]
        key = token[0:len(token) - 1]
        start_of_value = loc + len(token)
        value = msg[start_of_value:prev_loc]
        if value[-1] == ',':
            value = value[0:-1]
        prev_loc = loc - 1
        attrs[key] = value

    return attrs

def parse_state_from_value(value):
    """
    Helper function to find the state (Up/Down)
    There is a bug in 2.6/2.7 where the message contains JSON instead of
    the actual state value (up/down).  This function returns the correct
    value if it is JSON by parsing it and pulling out the 'state' attribute.
    Attributes:
    value - the value to parse/check
    Example value when JSON:
          old_state={u'name': u'tun-gw-aws-east-gw-azure-central',
                     u'rx_bytes': None, u'rtt_avg': u'N/A',
                     u'timestamp': u'2017-10-26 18:15:50.867069',
                     u'packet_transmit': 4,
                     u'modified': u'2017-10-26 18:15:50.867069', 
                     u'dst_gw': u'gw-azure-central', u'packet_receive': 1, 
                     u'state': u'Down', u'src_gw': u'gw-aws-east', 
                     u'rtt_max': 36.969, u'rtt_min': 36.969, u'tx_bytes': None,
                     u'rtt_mdev': 0.0, u'packet_loss': 75.0}

    Returns:
       the correct state (either what was passed or 'state' extracted from json)
    """

    if not value:
        return 'Unknown'

    if value[0] == '{':
        # we need to clean up this string a bit before it will parseable
        # convert all ' to "
        # remove the extraneous 'u' characters
        # change None to null
        json_str = (value
                    .replace("', u'", '", "')
                    .replace(", u'", ', "')
                    .replace("{u'", '{"')
                    .replace("': u'", '": "')
                    .replace("': ", '": ')
                    .replace('None', 'null'))
        value = json.loads(json_str)
        if 'state' in value:
            return value['state']
    else:
        return value

def process(data):
    """
    Processes the message received from rsyslog.  It is expected to be using
    a template to format the message before sending to this script.  See
    comments at top of this script for details on how to configure.

    Arguments:
    data - the message received.  expected to be in this format:
       DATE<TAB>MESSAGE<NEWLINE>
    """

    if not data:
        return

    parts = data.split('\t')
    if len(parts) != 2:
        return
    reported_date = dateutil.parser.parse(parts[0])
    msg = parts[1].strip()

    # find the message type
    # expecting something like this:
    # AviatrixTunnelStatusChange: blah blah blah ...
    type_loc = msg.find(':')
    msg_type = msg[0:type_loc].strip()
    if msg_type not in MESSAGES:
        print 'Ignoring message type "%s"' % (msg_type)
        return

    print "Handling '%s' ..." % (msg_type)
    content = msg[(type_loc + 1):]
    config = MESSAGES[msg_type]
    processing_function = globals()[config['processor']]
    # parse the message into its attribute name/value pairs as defined
    # by the configuration for this message type
    attrs = parse_tokens_from_string(config, content)
    if not attrs or not processing_function:
        return
    # call the configured processing function
    processing_function(config, reported_date, attrs)

def main():
    """
    The main run loop for this program.  Listens for events delivered to the
    socket and processes them using the process() function.
    """

    # workaround for 'InsecurePlatformWarning'
    import requests.packages
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # initialize datadog library
    datadog.initialize(**DDOG_OPTIONS)

    tunnels_thread = None
    sock = None
    try:
        # startup check tunnel thread
        tunnels_thread = TunnelCheck()
        tunnels_thread.daemon = True
        tunnels_thread.start()

        # open the local socket file and begin loop
        sock = opensocket(PORT)
        while True:
            connection, client_address = sock.accept()
            data = connection.recv(1024)
            if data:
                process(data)

    except KeyboardInterrupt:
        pass

    finally:
        if sock:
            sock.close()
        if tunnels_thread:
            tunnels_thread.stop()

class TunnelCheck(threading.Thread):
    """
    Background thread to check the status of the tunnels and report each
    to Datadog as a ServiceCheck.
    """

    def __init__(self):
        """
        Initialize this class and set up the stop event Event object
        """
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()

    def stop(self):
        """
        Stop processing (callable from the main() routine
        """
        self.stop_event.set()

    def run(self):
        """
        This function should be running in the background in a separate thread.
        It will periodically wake up and check the tunnel status and send a
        metric for each tunnel.
        """

        ucc_ip = '52.165.134.11'
        ucc_username = 'admin'
        ucc_password = 'P@ssw0rd!'
        while not self.stop_event.is_set():
            print 'Checking tunnel status ...'
            response = requests.get('https://%s/v1/api/?action=login&username=%s&password=%s' % (ucc_ip, ucc_username, ucc_password), verify=False)
            if response.status_code == 200:
                session_id = response.json()['CID']
                response = requests.get('https://%s/v1/api?action=list_peer_vpc_pairs&CID=%s' % (ucc_ip, session_id), verify=False)
                if response.status_code == 200:
                    # for each peer found, create a service check for each
                    # and submit to Datadog
                    for pair in response.json()['results']['pair_list']:
                        name = 'aviatrix.tunnel.up'
                        tags = ['gateway1:%s' % (pair['vpc_name1']),
                                'gateway2:%s' % (pair['vpc_name2'])]
                        message = ('%s <--> %s : %s' %
                                   (pair['vpc_name1'], pair['vpc_name2'],
                                    pair['peering_state']))
                        if pair['peering_state'] == 'Up':
                            status = datadog.api.constants.CheckStatus.OK
                        else:
                            status = datadog.api.constants.CheckStatus.CRITICAL
                        datadog.api.ServiceCheck.check(check=name, host=ucc_ip,
                                                       status=status,
                                                       message=message,
                                                       tags=tags)
                        print message

            print 'Sleeping ...'
            self.stop_event.wait(60)

if __name__ == "__main__":
    main()

    # Test Cases

    #process("Oct 29 12:28:04\tAviatrixTunnelStatusChange: src_gw=gw-gcp-v2(Gcloud us-east1) dst_gw=gw-azure-us-west(Azure ARM West US) old_state={u'name': u'tun-gw-gcp-v2-gw-azure-us-west', u'rx_bytes': None, u'rtt_avg': 75.434, u'timestamp': u'2017-10-29 12:28:14.755589', u'packet_transmit': 4, u'modified': u'2017-10-29 14:25:58.668573', u'dst_gw': u'gw-azure-us-west', u'packet_receive': 4, u'state': u'Up', u'src_gw': u'gw-gcp-v2', u'rtt_max': 75.766, u'rtt_min': 75.229, u'tx_bytes': None, u'rtt_mdev': 0.351, u'packet_loss': 0.0} new_state={u'name': u'tun-gw-gcp-v2-gw-azure-us-west', u'rx_bytes': None, u'rtt_avg': u'N/A', u'timestamp': u'2017-10-29 14:33:59.675654', u'packet_transmit': 4, u'modified': u'2017-10-29 14:33:59.675654', u'dst_gw': u'gw-azure-us-west', u'packet_receive': 4, u'state': u'Down', u'src_gw': u'gw-gcp-v2', u'rtt_max': 75.766, u'rtt_min': 75.229, u'tx_bytes': None, u'rtt_mdev': 0.351, u'packet_loss': 0.0}")
    #process('Oct 29 08:28:04\tAviatrixVPNSession: User=mike, Status=active, Gateway=gw-vpn-test, GatewayIP=34.215.112.231, VPNVirtualIP=192.168.43.6, PublicIP=N/A, Login=2017-10-29 10:29:00, Logout=N/A, Duration=N/A, RXbytes=N/A, TXbytes=N/A')
    #process('Oct 29 05:28:04\tAviatrixVPNSession: User=mike, Status=disconnected, Gateway=gw-vpn-test, GatewayIP=34.215.112.231, VPNVirtualIP=192.168.43.6, PublicIP=N/A, Login=2017-10-29 10:29:00, Logout=2017-10-29 12:38:35, Duration=0:0:9:35, RXbytes=11.92KB, TXbytes=12.84MB')
    #process('Oct 30 12:28:04\tAviatrixLicsenseVPNUsers: users=1')
    #process('Oct 30 16:06:04\tAviatrixLicsenseVPNUsers: users=5')
    #process('Oct 30 14:06:04\tAviatrixLicsenseVPNUsers: users=10')

    #process('Oct 26 21:28:04\tAviatrixGwSysStats: timestamp=2017-10-26 21:26:05.241227 name=gw-aws-east cpu_idle=100 memory_free=241588 disk_total=8115168 disk_free=4829980')
    #process('Oct 26 21:28:04\tAviatrixGwNetStats: timestamp=2017-10-26 21:30:06.238383 name=gw-aws-east public_ip=34.235.255.76 private_ip=172.31.22.48 interface=eth0 total_rx_rate=7.95Kb total_tx_rate=3.57Kb total_rx_tx_rate=11.5Kb')
