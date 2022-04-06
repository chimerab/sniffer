# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.inet import TCP

from redis_protocol import *
from scapy.fields import StrField

import logging

logger = logging.getLogger(__name__)


class Redis(Packet):
    name = 'Redis'
    fields_desc = [
        StrField('TYPE', '', fmt='H'),
        StrField('OP', '', fmt='H'),
        StrField('OBJ', '', fmt='H'),
        StrField('EXTRA', '', fmt='H')
    ]
    show_indent = 2
    DELIMITER = '\r\n'

    @classmethod
    def tcp_reassemble(cls, data, metadata):
        """[called by sniff(session=TCPSession),
        reassembles the tcp stream if packet spans over multiple TCP packets]

        Args:
            data (bytes): [a raw bytes of payload]
            metadata ([dict]): [stores partial streams]

        Returns:
            [Packet]: [reassembled Packet]
        """

        logger.debug(f'tcp reassemble input first 50 bytes: {data[:50]}, total length: {len(data)}')

        try:
            result, length = decode(data)
            logger.debug(f'tcp reassemble result: {result}, length:{length}')
        except Exception as e:
            result = None
            logger.info(f'decode exception:{e} for input data: {data}')

        # None mean content not complete, we need push back to queue.
        if result is None or length != len(data):
            logger.debug(f'tcp reassemble not finished. data length: {len(data)}')
            return None
        else:
            redis_packet = Redis(data)

            length = len(result)
            if length == 1:
                redis_packet.setfieldval('OP', result[0])
            elif length == 2:
                redis_packet.setfieldval('OP', result[0])
                redis_packet.setfieldval('OBJ', result[1])
            elif length == 0: # b'$0\r\n\r\n'
                redis_packet.setfieldval('OP', result)
            else:
                try:
                    redis_packet.setfieldval('OP', result[0])
                except Exception as e:
                    logger.debug(f'error while set result:f{e}')
                redis_packet.setfieldval('OBJ', result[1])

            logger.debug(f'tcp reassemble finished. data length: {len(data)}')
            return redis_packet

    def mysummary(self):
        return self.sprintf(
            'Redis: %Redis.TYPE% %Redis.OP% %Redis.OBJ% %Redis.EXTRA%'
        )

    def guess_payload_class(self, s):
        result, length = decode(s)
        if result is None:
            return Raw

        return Redis


bind_layers(TCP, Redis, dport=6379)
bind_layers(TCP, Redis, sport=6379)

