"""
redis command time consumption calculator
"""

from scapy.all import *
from collections import deque
from threading import Thread
from multiprocessing import Process

from scapy.layers.inet import TCP, IP

#DO NOT REMOVE BELOW IMPORT
import redis
import os
import csv
import socket
import time
import boto3
import argparse

import tracemalloc

logger = logging.getLogger(__name__)
formatter = '%(asctime)s - %(filename)s - %(funcName)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO,
                    filename='output.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format=formatter)

# 1M packet 'normally' will take 500M - 1G memory
g_queue = deque(maxlen=1000000)
g_flow = {}
g_packet_remove_count = 0
g_packet_add_count = 0
g_parameters = {}
g_write = None


def output(path='.', size=1, s3path=None):
    client = None
    bucket = None
    folder = None
    if s3path is not None:
        client = boto3.client('s3')
        path_parts = s3path.replace('s3://', '').split('/')
        bucket = path_parts.pop(0)
        folder = '/'.join(path_parts)

    def upload_file(s3client, file_name, bucket, object_name=None):
        """Upload a file to an S3 bucket

        :param s3client: s3 client
        :param file_name: File to upload
        :param bucket: Bucket to upload to
        :param object_name: S3 object name. If not specified then file_name is used
        :return: True if file was uploaded, else False
        """

        # If S3 object_name was not specified, use file_name
        if object_name is None:
            object_name = os.path.basename(file_name)

        # Upload the file
        try:
            response = s3client.upload_file(file_name, bucket, object_name)
        except Exception as e:
            logger.error(f'Failed to upload file to s3: {e}')
            return False
        return True

    def gen_filename(parent: str):
        hostname = socket.gethostname()
        filename = parent + '/' + hostname + '_' + str(os.getpid()) + '_' + str(time.time()).replace('.', '') + '.csv'
        return filename

    filename = gen_filename(path)

    print(f'first output file: {filename}')
    logger.info(filename)
    buffer = []

    def save(entry: list):

        nonlocal buffer
        nonlocal filename
        nonlocal client
        nonlocal s3path
        nonlocal bucket
        nonlocal folder

        buffer.append(entry)
        if len(buffer) >= 100:
            with open(filename, 'a+', newline='') as fp:
                writer = csv.writer(fp)
                writer.writerows(buffer)
            buffer.clear()
            if os.stat(filename).st_size >= size * 1024 * 1024:
                if s3path is not None:
                    ret = upload_file(client, filename, bucket, object_name=folder + os.path.basename(filename))
                    if ret is True:
                        logger.info(f'upload file {filename} to s3 successful.')
                filename = gen_filename(path)

    return save


def handler(pkt: Packet) -> None:
    global g_packet_remove_count

    tcplayer = pkt.getlayer('TCP')
    if tcplayer is not None:
        tcp_flow_handler(pkt)
    else:
        logger.info('not a tcp packet. drop it')

    g_packet_remove_count += 1
    logger.debug(f'---packet been handled from the queue: {g_packet_remove_count}')


def tcp_flow_handler(pkt: Packet) -> None:
    global g_write

    snd_fmt = ('TCP {IP:%IP.src%}{IPv6:%IPv6.src%}:%r,TCP.sport% > ' +
               '{IP:%IP.dst%}{IPv6:%IPv6.dst%}:%r,TCP.dport%')
    rcv_fmt = ('TCP {IP:%IP.dst%}{IPv6:%IPv6.dst%}:%r,TCP.dport% > ' +
               '{IP:%IP.src%}{IPv6:%IPv6.src%}:%r,TCP.sport%')

    if len(pkt[TCP].payload) == 0:
        logger.info('empty ack packet. drop it.')
        logger.debug(pkt[IP].summary)
        return

    # current 4 tuple tcp flow
    snd_flow_key = pkt.sprintf(snd_fmt)
    rcv_flow_key = pkt.sprintf(rcv_fmt)

    logger.debug(pkt[IP].summary)
    # we need check bi-direction packet match

    if rcv_flow_key in g_flow:
        packet_list = g_flow.get(rcv_flow_key)
    elif snd_flow_key in g_flow:
        packet_list = g_flow.get(snd_flow_key)
    else:
        logger.debug(f'new flow found: {snd_flow_key}')
        g_flow[snd_flow_key] = [pkt]
        return

    if pkt[TCP].sport == 6379:
        logger.debug('packet sport 6379, treat as RSP')
        for i in range(len(packet_list) - 1, -1, -1):
            if packet_list[i][TCP].sport != 6379:
                time_used = pkt.time - packet_list[i].time
                entry = [str(packet_list[i].time),
                         str(packet_list[i][IP].src),
                         str(packet_list[i][TCP].sport),
                         packet_list[i].OP.decode(),
                         packet_list[i].OBJ.decode().replace('\r', ' ').replace('\n', ' '),
                         str(round(time_used * 1000, 3))]
                logger.debug('add metrics entry.')
                g_write(entry)
                logger.debug(f'REQ time: {packet_list[i].time} BODY: {packet_list[i].getlayer("Redis").summary}')
                logger.debug(f'RSP time: {pkt.time} BODY: {pkt.getlayer("Redis").summary}')
                packet_list.pop(i)
                return
    elif pkt[TCP].dport == 6379:
        logger.debug('packet dport 6379, treat as REQ')
        # we will clear the list then add new REQ packet, this mean only one packet will be in the list for now.
        packet_list.clear()
        packet_list.append(pkt)
    else:
        logger.info('not a redis packet since src port and dst port is not 6379')


def worker() -> None:
    global g_parameters

    previous = time.time()
    previous_pkt_count = g_packet_add_count
    while True:
        now = time.time()
        if now - previous >= 5:  # report statistics every 5 seconds.
            debug_flag = g_parameters['debug']
            report_statistics(debug=debug_flag)
            if previous_pkt_count == g_packet_add_count:
                print('\nno packets been added to work queue. finish work.')
                logger.info('no packets been added to work queue. finish work.')
                break
            previous_pkt_count = g_packet_add_count
            previous = now

        size = len(g_queue)
        if size == 0:
            time.sleep(0.001)
            continue

        packet = g_queue.popleft()
        try:
            handler(packet)
        except Exception as e:
            logger.info(f'exception in packet handler:{e} for {packet}')

    print('worker thread complete')


def report_statistics(debug=False) -> None:
    fstring = f'packets captured: {g_packet_add_count:8} packets analysis: {g_packet_remove_count:8} packets in queue: {len(g_queue):8}'
    if debug is False:
        print(fstring, end='\r', flush=True)
        logger.info(fstring)
        return

    print(fstring)
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')
    for stat in top_stats[:10]:
        print(f'>>> memory usage: {stat}')
        logger.debug(f'>>> memory usage: {stat}')


def distribute(pkt: Packet) -> None:
    global g_packet_add_count
    g_packet_add_count += 1
    g_queue.append(pkt)
    time.sleep(0.001)
    logger.debug(f'+++packet ben added to the queue: {g_packet_add_count}')


def parse_command():
    global g_parameters

    parser = argparse.ArgumentParser()

    # common parameter
    parser.add_argument('--filter', '-f', default='port 6379', help='tcpdump format filter.')
    parser.add_argument('--debug', '-d', action="store_true", help='turn on debug output in logs.')
    parser.add_argument('--time', '-t', type=int, default=10, help='how many minutes script will run.')
    parser.add_argument('--input_file', '-i', default=None, help='analysis a pcap file otherwise will capture packet '
                                                                 'on eth0')
    parser.add_argument('--output_folder', '-o', default='.', help='output file path, do not specify filename.')
    parser.add_argument('--s3path', '-s3', default=None, help='the s3 path you want to upload file to.')
    args = parser.parse_args()

    g_parameters['filter'] = args.filter
    g_parameters['debug'] = args.debug
    g_parameters['time'] = args.time
    g_parameters['input_file'] = args.input_file
    g_parameters['output_folder'] = args.output_folder
    g_parameters['time'] = args.time
    g_parameters['s3path'] = args.s3path


def producer(filter: str):
    pass


def main():
    global g_parameters
    global g_write

    parse_command()
    logger.info(f'input parameters: {g_parameters}')

    if g_parameters['debug'] is True:
        tracemalloc.start()

    g_write = output(g_parameters['output_folder'], size=10, s3path=g_parameters['s3path'])

    start = time.time()
    print(f'time start: {time.ctime()}')

    # producer(g_parameters['filter'] + ' and port 6379')

    thread = Thread(target=worker)
    thread.start()

    if g_parameters['input_file'] is not None:
        sniff(offline=g_parameters['input_file'],
              filter=g_parameters['filter'] + ' and port 6379',
              session=TCPSession,
              # count=5000,
              store=False,
              prn=distribute)
    else:
        sniff(iface='eth0',
              filter=g_parameters['filter'] + ' and port 6379',
              session=TCPSession,
              # count=5000,
              store=False,
              prn=distribute)

    thread.join()

    end = time.time() - start
    print(f'time now and cost: {time.time()} {end}')


if __name__ == '__main__':
    main()
