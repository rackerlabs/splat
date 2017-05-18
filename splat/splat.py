#!/usr/bin/env python3.6

from datetime import timedelta
import os
import sys
import tempfile
import time

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


def report(days):
    days_to_report = arrow.utcnow().replace(days=-int(days)).timestamp
    j = journal.Reader()
    j.seek_realtime(days_to_report)
    j.add_match(APPLICATION="splat")
    stories = []
    for entry in j:
        stories.append(entry['PTID'])

    print(stories)


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
    if 'VAULT_AUTH_TOKEN' in os.environ:
        client.token = os.environ['VAULT_AUTH_TOKEN']
    elif 'VAULT_AUTH_GITHUB_TOKEN' in os.environ:
        client.auth_github(token=os.environ['VAULT_AUTH_GITHUB_TOKEN'])
    else:
        raise Exception("No Vault Auth environment variables provided.")
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
