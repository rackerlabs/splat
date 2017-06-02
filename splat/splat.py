#!/usr/bin/env python3.6

from datetime import timedelta
import os
import sys
import tempfile
import time
from collections import defaultdict, OrderedDict

try:
    package_index = sys.path.index('/usr/lib/python3.6/dist-packages')
    sys.path.append(sys.path.pop(package_index))
except ValueError:
    pass

try:
    package_index = sys.path.index('/usr/lib/python3/dist-packages')
    sys.path.append(sys.path.pop(package_index))
except ValueError:
    pass

import arrow
from docopt import docopt
import hvac
import json
import requests
import signal
from systemd import journal

REMAINING = 0
PAUSED = False


# This will cause tmp files to be cleaned up when PID is sent the kill signal.
def receive_signal(signum, stack):
    sys.exit()


def pause(signum, stack):
    global PAUSED
    PAUSED = not PAUSED
    if PAUSED:
        print("Paused")
    else:
        print("Continuing")


signal.signal(signal.SIGTERM, receive_signal)
signal.signal(signal.SIGINT, receive_signal)
signal.signal(signal.SIGUSR1, pause)


def main(arguments):
    if arguments['start']:
        start(arguments)
    elif arguments['status']:
        status()
    elif arguments['pause']:
        send_pause(arguments)
    elif arguments['report']:
        report(arguments['DAYS'])

#{
#	"4323423": {
#		"chunks": [{
#				"date": "somedate",
#				"users": ["bk", "mb"],
#				"tags": ["blah", "blahblah"]
#			},
#			{
#				"date": "somedate",
#				"users": ["bk", "mb"]
#			}
#		]
#	}
#}

def report(days):
    rdata = defaultdict(lambda:{'chunks':[],'labels':[],'name':""})
    days_to_report = arrow.utcnow().replace(days=-int(days)).timestamp
    j = journal.Reader()
    j.seek_realtime(days_to_report)
    j.add_match(APPLICATION="splat")
    for entry in j:
        add_entry(entry, rdata)
    for ptid, data in rdata.items():
        time_spent = 0
        for chunk in data['chunks']:
            time_spent += len(chunk['users']) * 25
        rdata[ptid]['time_spent'] = time_spent

    print("__Time per story__")
    time_per_story(rdata)
    print("\n")
    print("__Time per label__")
    time_per_label(rdata)


def time_per_story(rdata):
    time_list = []
    for ptid, data in rdata.items():
        time_spent = timedelta(minutes=data['time_spent'])
        time_list.append((ptid, time_spent, data['name']))
    s_list = sorted(time_list, key=lambda x: x[1], reverse=True)

    for ptid, time_spent, name in s_list:
        print(f"{ptid} {time_spent} {name}")

def time_per_label(rdata):
    labels = defaultdict(lambda: 0)
    for ptid, data in rdata.items():
        for label in data['labels']:
            labels[label] += rdata[ptid]['time_spent']
    label_list = [(label, time_spent,)for label, time_spent in labels.items()]
    s_list = sorted(label_list, key=lambda x: x[1], reverse=True)
    for label, time_spent in s_list:
        td=timedelta(minutes=time_spent)
        print(f"{label} {td}")

def add_entry(entry, rdata={}):
    ptid=entry['PTID']
    story_data = get_ptid(ptid)
    rentry = {
            "date": entry['__REALTIME_TIMESTAMP'],
            "users": entry['PAIRS'].split(','),
            }
    rdata[ptid]['labels']=[label['name'] for label in story_data['labels']]
    rdata[ptid]['chunks'].append(rentry) 
    rdata[ptid]['name'] = story_data['name']
   
def send_pause(arguments):
    pairs = set(arguments['PAIRS'].split(","))
    try:
        pid = get_pid_from_pairs(pairs)
    except:
        print("Session pairs not found.")
        sys.exit()
    os.kill(pid, signal.SIGUSR1)


def start(arguments):
    global PAUSED
    PAUSED = False

    try:
        story_response = get_ptid(arguments['PTID'])
    except requests.exceptions.HTTPError:
        print(f"The story {arguments['PTID']} was not found.")
        sys.exit()

    print(f"Starting work on story: {story_response['name']}")

    tempdir = '/tmp/splat'

    try:
        os.mkdir(tempdir)
        os.chown(tempdir, -1, 100)
        os.chmod(tempdir, 0o1777)
    except FileExistsError:
        pass

    mypid = str(os.getpid()) + "\n"

    tempfile.tempdir = tempdir
    fp = tempfile.NamedTemporaryFile(suffix=".{}".format(str(os.getpid())))
    fp.write(str.encode(str(arrow.utcnow()) + "\n"))
    fp.write(str.encode(mypid))
    fp.write(str.encode(arguments['PAIRS'] + "\n"))
    fp.flush()
    os.chown(fp.name, -1, 100)
    os.chmod(fp.name, 0o664)

    journal.send(
        MESSAGE='Starting Pomodoro. {} are working on {}'.format(
            arguments['PAIRS'], arguments['PTID']),
        APPLICATION='splat',
        PRIORITY="NOTICE",
        PAIRS=f"{arguments['PAIRS']}",
        PTID=f"{arguments['PTID']}",
    )

    global REMAINING

    REMAINING = 25*60
    while (REMAINING > 0):
        if PAUSED:
            time.sleep(5)
            continue
        fp.write(str.encode(str(REMAINING).zfill(4) + "\n"))
        fp.flush()
        time.sleep(5)
        REMAINING -= 5
        string_size = len(str.encode(str(REMAINING).zfill(4) + "\n"))
        fp.seek(-string_size, 1)


def status():
    clean_stale_files()
    temp_files = splat_tempfiles()
    statusbar = ""
    for f in temp_files:
        tmpfile = open("/tmp/splat/" + f, 'r')
        lines = tmpfile.readlines()
        timestr = str(timedelta(seconds=int(lines[3].strip("\n"))))
        statusbar += "{}: {}|".format(lines[2].strip("\n"), timestr)
    if statusbar != "":
        print("|" + statusbar)


def splat_tempfiles():
    return os.listdir("/tmp/splat")


def clean_stale_files():
    temp_files = splat_tempfiles()
    for f in temp_files:
        tmpfile = open("/tmp/splat/" + f, 'r')
        lines = tmpfile.readlines()
        creation_date = arrow.get(lines[0].strip("\n"))
        if (arrow.utcnow() - creation_date).seconds > 3000:
            os.remove("/tmp/splat/" + f)


def get_pid_from_pairs(pairs):
    temp_files = splat_tempfiles()
    for f in temp_files:
        tmpfile = open("/tmp/splat/" + f, 'r')
        lines = tmpfile.readlines()
        pairs_from_file = set(lines[2].strip("\n").split(","))
        if pairs_from_file == pairs:
            return int(lines[1].strip("\n"))
    else:
        raise


def connect_to_vault():
    client = hvac.Client(url=os.environ['VAULT_ADDR'])
    PATH=os.path.expanduser('~/.vault-token')
    if os.path.isfile(PATH) and os.access(PATH, os.R_OK):
        with open(PATH, "r") as F:
            client.token = F.read()
    elif 'VAULT_AUTH_TOKEN' in os.environ:
        client.token = os.environ['VAULT_AUTH_TOKEN']
    else:
        raise Exception("No auth token could be found. Try authing with Vault.")
    return client


def vault_read(path):
    client = connect_to_vault()
    response = client.read(path)
    return _vault_strip_response(response)


def _vault_strip_response(response):
    if not response or 'data' not in response:
        raise KeyError("Vault did not respond with a secret as expected.")
    return response['data']


def get_ptid(ptid):
    vault_entry = vault_read("/mpcf/automation/splat/params")
    pivotal_api_token = vault_entry.get('pivotal_api_token')
    pivotal_story_api = "https://www.pivotaltracker.com/services/v5/stories/{}"
    headers = {'X-TrackerToken': pivotal_api_token}

    response = requests.get(pivotal_story_api.format(ptid), headers=headers)
    response.raise_for_status()
    return json.loads(response.text)


if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
