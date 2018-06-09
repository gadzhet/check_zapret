#!/usr/bin/python
# encoding: utf8
import os
import sys
import urllib2
import socket
import time
import datetime as dt
import xml.etree.ElementTree as Et
import multiprocessing as mp
import idna
import urlparse
import logging
from argparse import ArgumentParser


cliparse = ArgumentParser()
cliparse.add_argument('-l', '--log', default='/var/log/zapret_checker.log', help='Path and name of file log. '
                                                                                 'Default: /var/log/zapret_checker.log')
cliparse.add_argument('-d', '--debug', default=0, type=int, help='Level of debug. Low 0 High 4. Default 0 is off')
cliparse.add_argument('-f', '--file', default='/noc/zapret/dump.xml', help='XML dump file of RKN.')
cliparse.add_argument('-r', '--result', default='/var/log/zapret_result.log', help='File with validation result.')
cliparse.add_argument('-p', '--proc', default=100, type=int, help='Count of processes per core. Default 100.')
cliargs = cliparse.parse_args()

LOG_LEVEL = {0: 'NOTSET',
             1: 'INFO',
             2: 'WARNING',
             3: 'ERROR',
             4: 'DEBUG'}


def run_once(file_of_pid):
    """Guardian to prevent the launch of multiple copies.
     Exits if one copy is already running.
    :param file_of_pid: Path for tmp file of pid
    """
    if os.path.exists(file_of_pid):
        fpid = open(file_of_pid)
        # Checking the existence of pid
        if os.path.exists('/proc/{}/status'.format(fpid.read())):
            sys.exit(0)
        fpid.close()

    # Creating file with pid
    f = open(file_of_pid, 'w')
    f.write('{}'.format(os.getpid()))
    f.close()


def getter(domain):
    """Getting status code for domain or URL
    :param domain: domain name or URL as str
    :return: returned True if status code equals 200 OK
    """
    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'http://' + domain
    normal_code = [403, 404, 451]
    # Errors that we expect
    error_list = [socket.EAI_NONAME, socket.errno.ECONNRESET, socket.errno.ECONNREFUSED,
                  socket.errno.EHOSTUNREACH, socket.errno.ENETUNREACH, socket.EAI_AGAIN,
                  socket.EAI_NODATA, socket.SSL_ERROR_SSL, socket.errno.EADDRNOTAVAIL,
                  socket.error.errno]
    # Make a request and get the response code
    try:
        # Making a query
        request = urllib2.Request(domain)
        request.add_header('User-agent', 'Chrome/65.0.3325.181 (Linux RKN)')

        response = urllib2.urlopen(request, timeout=2)
        if response.code == 200:
            response.close()
            log.warning('URL avail: {}'.format(domain))
            return True

    except urllib2.HTTPError as e:
        if e.code not in normal_code:
            log.debug('urllib2.HTTPError: {}'.format(e))

    except urllib2.URLError as e:
        if e.reason[0] == 'timed out':
            # This exception can be if you exceed conntrack
            # Remember this, and if you need to change the conntrack restriction
            pass
        elif e.reason[0] not in error_list:
            log.debug('urllib2.URLError: {}'.format(e))

    except socket.error as e:
        if e != 'timed out':
            log.debug('SocketErr: {}'.format(e))

    except IOError as e:
        log.debug('IOerror: {}'.format(e))

    except Exception as e:
        log.debug('Unknown exception: {}'.format(e))


def _queue_manager(input_queue, output_queue):
    """Receives the URL from the queue, starts the check, and places the result in the output queue
    :param input_queue: Queue with URLs
    :param output_queue: Queue for write passes
    """
    try:
        while True:
            domain = input_queue.get()
            if domain:
                output_queue.put(getter(domain))
    except KeyboardInterrupt:
        SystemExit(1)


def _counter(output_queue, avail):
    """Pass counter.
    :param output_queue:
    :param avail:
    """
    try:
        while True:
            if output_queue.get():
                avail.value += 1
    except KeyboardInterrupt:
        SystemExit(1)


def starter(domain_list):
    """Create queue subprocesses and add URLs to the queue
    :param domain_list: prepared list of URLs
    :return: dictionary where:
     'len' length of domain_list
     'avail' count of available URLs
     'percent' count of available URLs in percentage
    """
    # Shared variable for counting passes
    avail = mp.Value('i', 0)
    # Set the number of processes multiplied by the number of cores
    number_of_processes = mp.cpu_count()*cliargs.proc
    log.debug('{} subprocesses will be created'.format(number_of_processes))
    # Create queues
    input_queue = mp.Queue()
    output_queue = mp.Queue()
    # Process for the pass count
    mp.Process(target=_counter, args=(output_queue, avail)).start()
    try:
        # Run worker processes
        for i in range(number_of_processes):
            mp.Process(target=_queue_manager, args=(input_queue, output_queue)).start()
        log.debug('Subprocesses created')
        for dome in domain_list:
            input_queue.put(dome)
        # Wait until all queues are empty
        while not input_queue.empty():
            time.sleep(0.01)
    except KeyboardInterrupt:
        log.debug('User interrupted processes')
        print('\n\n\033[93mPlease wait. Work is terminating.\033[0m\n\n')

        output_queue.close()
        output_queue.join_thread()
        input_queue.close()
        input_queue.join_thread()

        print('\033[92mThe queue is cleared.\033[0m')

        for child in mp.active_children():
            child.terminate()

        print('\033[92mWork completed.\033[0m')
        sys.exit(0)

    log.debug('Clearing queues')
    output_queue.close()
    output_queue.join_thread()
    input_queue.close()
    input_queue.join_thread()

    # Terminating all children
    log.debug('The child processes are terminated')
    for child in mp.active_children():
        child.terminate()
    # We are waiting for all the processes to finish work.
    for child in mp.active_children():
        child.join()
    log.debug('All children stopped work')

    return dict(len=len(domain_list), avail=avail.value,
                percent=float(avail.value) / float(len(domain_list)) * 100 if avail.value > 0 else 0)


def parse_dump(dump=''):
    """Parsing the XML file and getting URLs and DOMAINs
    :param dump: https://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf
    :return: tuple of prepared URLs and DOMAINs
    """
    dmp_xml = Et.parse(dump).getroot()
    urls = []
    for cont in dmp_xml.findall('content'):
        blocktype = cont.get('blockType')

        if blocktype == 'url' or not blocktype:
            url = cont.find('url')

            if hasattr(url, 'text'):
                parsed_url = urlparse.urlparse(url.text)
                orig_scheme = parsed_url.scheme
                orig_domain = parsed_url.netloc

                try:
                    domain = idna.encode(orig_domain)
                except idna.core.IDNAError:
                    domain = orig_domain.encode('idna')

                path = url.text.split(u'{}://{}'.format(orig_scheme, orig_domain))[1].encode('utf-8')
                urls.append('{}://{}{}'.format(orig_scheme, domain, path))
        elif blocktype == 'domain':
            bt_domain = cont.find('domain')

            if hasattr(bt_domain, 'text'):
                try:
                    bt_domain = idna.encode(bt_domain.text)
                except idna.core.IDNAError:
                    bt_domain = bt_domain.text.encode('idna')

                urls.append(bt_domain)
    log.debug('Number of records to check: {}'.format(len(urls)))
    return tuple(urls)


if __name__ == '__main__':
    # Finish work if a copy of the script is started
    run_once('/tmp/zapret-checker.pid')

    log = logging.getLogger('zapret-checker')
    # File for logging
    hdlr = logging.FileHandler(cliargs.log)
    # Log format
    formatter = logging.Formatter('%(asctime)s %(process)d/%(threadName)s %(levelname)s : %(message)s')
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    # Set the Logging Level
    if cliargs.debug not in range(5):
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(LOG_LEVEL.get(cliargs.debug))

    log.debug('Work is started.')
    start = time.time()

    if os.path.exists(cliargs.file):
        domains = parse_dump(cliargs.file)
        if len(domains) == 0:
            log.error('The domain list is empty. Work is stopped.')
            sys.exit(1)
    else:
        log.error('Dump file does not exist')
        sys.exit(1)

    result = starter(domains)

    try:
        with open(cliargs.result, 'w') as res:
            res.write('size={}\navail_count={}\navail_percent={}\n'.format(
                result.get('len'), result.get('avail'), result.get('percent')))
    except IOError:
        log.error('Can not write to {}'.format(cliargs.result))

    log.debug('Work time: {}'.format(dt.timedelta(seconds=(time.time() - start))))
