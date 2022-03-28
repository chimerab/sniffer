# -*- coding: utf-8 -*-


from scapy.all import *
import sys
import logging
import boto3
import csv

logger = logging.getLogger(__name__)
formatter = '%(asctime)s - %(filename)s - %(funcName)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO,
                    filename='capture.log',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    format=formatter)


class Writer(object):

    def __init__(self, path='.', max_size=1, s3path=None):
        self.path = path
        self.client = None
        self.bucket = None
        self.folder = None
        self.max_size = max_size
        self.filename = 'unknown'
        self.s3path = s3path
        self.pkt_writer = None

        if s3path is not None:
            self.client = boto3.client('s3')
            path_parts = s3path.replace('s3://', '').split('/')
            self.bucket = path_parts.pop(0)
            self.folder = '/'.join(path_parts)

        self.filename = self.generate_filename(path)
        self.pkt_writer = PcapWriter(self.filename, append=True)

        print(f'first output file: {self.filename}')
        logger.info(self.filename)

    def upload_file(self, s3client, file_name, bucket, object_name=None):
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

    def generate_filename(self, parent: str):
        hostname = socket.gethostname()
        filename = parent + '/' + hostname + '_' + str(os.getpid()) + '_' + str(time.time()).replace('.', '') + '.pcap'
        return filename

    def save(self, pkt: Packet):

        try:
            self.pkt_writer.write(pkt)
        except Exception as e:
            logger.error(f'unable to write to log file. {e}')

        if os.stat(self.filename).st_size >= self.max_size * 1024 * 1024:
            self.pkt_writer.close()
            if self.s3path is not None:
                ret = self.upload_file(self.client, self.filename, self.bucket,
                                       object_name=self.folder + os.path.basename(self.filename))
                if ret is True:
                    logger.info(f'upload file {self.filename} to s3 successful.')
                    os.remove(self.filename)
            self.filename = self.generate_filename(self.path)
            print(f'output file: {self.filename}')
            logger.info(self.filename)
            del self.pkt_writer
            self.pkt_writer = PcapWriter(self.filename, append=True)

    def close(self):
        try:
            self.pkt_writer.close()
            if self.s3path is not None:
                ret = self.upload_file(self.client, self.filename, self.bucket,
                                       object_name=self.folder + os.path.basename(self.filename))
                if ret is True:
                    logger.info(f'upload file {self.filename} to s3 successful.')
                    os.remove(self.filename)

        except Exception as e:
            logger.error(f'unable to write to log file. {e}')


writer = None


def handler(pkt: Packet):
    writer.save(pkt)


def main():
    global writer

    if len(sys.argv) < 2:
        print(f'usage: {sys.argv[0]} <interface> <s3path>\n'
              f'Ex: script.py eth0 s3://bucket_name/folder/\n')
        sys.exit(1)

    dev = sys.argv[1]
    s3path = sys.argv[2]
    writer = Writer(path='.', max_size=1, s3path=s3path)

    try:
        sniff(iface=dev, filter='port 6379', prn=handler)
    except KeyboardInterrupt:
        pass

    writer.close()
    print('capture finished.')


if __name__ == '__main__':
    main()
