#!/usr/bin/env python3.6
"""Splat Pomodoro Timer

Usage:
  splat start PTID PAIRS
  splat status
  splat pause PAIRS
  splat (-h | --help)

Arguments:
  PTID		Pivotal Tracker ID
  PAIRS		Comma separated list of initials

Examples:
  splat start 194492 bl,sk
  splat start 194492 mb
  splat pause bl,sk

Options:
  -h --help     Show this screen.
"""

from datetime import timedelta
from docopt import docopt
from systemd import journal
import signal
import os
import sys
import time
import tempfile
import glob
import arrow

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
        message='Starting Pomodoro',
        priority=journal.Priority.NOTICE,
        PAIRS=f"{arguments['PAIRS']}",
        PTID=f"{arguments['PTID']}",
    )

    global REMAINING

    REMAINING = 25*60
    while (REMAINING > 0):
        if PAUSED:
            time.sleep(5)
            continue
        fp.write(str.encode(str(REMAINING) + "\n"))
        fp.flush()
        time.sleep(5)
        REMAINING -= 5
        string_size = len(str.encode(str(REMAINING) + "\n"))
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

if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
