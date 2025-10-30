from __future__ import print_function

import logging
import os
import re
import socket
import sys
import time
from logging.handlers import SysLogHandler


class CustomFormatter(logging.Formatter):
    HOSTNAME = re.sub(
        r':\d+$', '', os.environ.get('SITE_DOMAIN', socket.gethostname()))
    FORMAT = '%(name)s[%(process)d]: %(message)s'.\
        format(hostname=HOSTNAME)

    converter = time.gmtime

    def __init__(self):
        super(CustomFormatter, self).__init__(fmt=self.FORMAT)

    def formatTime(self, record, datefmt=None):
        formatted = super(CustomFormatter, self).formatTime(
            record, datefmt=datefmt)
        return formatted + '.%03dZ' % record.msecs

    def format(self, record):        
        message = super(CustomFormatter, self).format(record)
        message = message.replace('\n', ' ')
        message += '\n'
        return message

class CleanSysLogHandler(SysLogHandler):
    # https://github.com/python/cpython/blob/064e989de50e37c8e79d3328a05804d72137e917/Lib/logging/handlers.py#L986
    append_nul = False


def get_headers(line):
    return dict([x.split(':') for x in line.split()])


def eventdata(payload):
    headerinfo, data = payload.split('\n', 1)
    headers = get_headers(headerinfo)
    return headers, data


def supervisor_events(stdin, stdout):
    while True:
        stdout.write('READY\n')
        stdout.flush()

        line = stdin.readline()
        headers = get_headers(line)

        payload = stdin.read(int(headers['len']))
        event_headers, event_data = eventdata(payload)

        yield event_headers, event_data

        stdout.write('RESULT 2\nOK')
        stdout.flush()


def main():
    try:
        host = os.environ['SYSLOG_SERVER']
        port = int(os.environ['SYSLOG_PORT'])
    except KeyError:
        sys.exit("SYSLOG_SERVER, SYSLOG_PORT are required.")

    handler = CleanSysLogHandler(
        address=(host, port),
        socktype=socket.SOCK_STREAM,
    )
    handler.setFormatter(CustomFormatter())

    for event_headers, event_data in supervisor_events(sys.stdin, sys.stdout):
        event = logging.LogRecord(
            name=event_headers['processname'],
            level=logging.INFO,
            pathname=None,
            lineno=0,
            msg=event_data,
            args=(),
            exc_info=None,
        )
        event.process = int(event_headers['pid'])
        handler.handle(event)


if __name__ == '__main__':
    main()
