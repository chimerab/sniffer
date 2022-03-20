# -*- coding: utf-8 -*-
# !/usr/bin/env python
DELIMITER = b'\r\n'


def encode(*args):
    "Pack a series of arguments into a value Redis command"
    result = []
    result.append("*")
    result.append(str(len(args)))
    result.append(DELIMITER)
    for arg in args:
        result.append("$")
        result.append(str(len(arg)))
        result.append(DELIMITER)
        result.append(arg)
        result.append(DELIMITER)
    return "".join(result)


def decode(data):
    """
    Decode redis byte
    :param data: redis bytes
    :return: tuple, first element is payload been decoded. second is byte length been decoded.
    """
    if len(data) == 0:
        return None, None

    # unable to find '\r\n'
    processed, index = 0, data.find(DELIMITER)
    if index == -1:
        return None, None
    
    # redis command ends with 'r\n'
    if data.endswith(DELIMITER) is False:
        return None, None

    # use range to get bytes, or you will get an int
    term = data[processed:1]
    if term == b'*':
        return parse_multi_chunked(data)
    elif term == b'$':
        return parse_chunked(data)
    elif term == b'+':
        return parse_status(data)
    elif term == b'-':
        return parse_error(data)
    elif term == b':':
        return parse_integer(data)


def parse_multi_chunked(data):
    index = data.find(DELIMITER)

    count = int(data[1:index])
    result = []
    start = index + len(DELIMITER)

    if count == 0:  # b'*0\r\n'
        return '0', start
    elif count == -1:  # b'*-1\r\n'
        return '-1', start

    # since each element with endswith 'r\n' so we at least should find "count" of '\r\n'
    if data[start:].count(DELIMITER) < count:
        return None, None

    for i in range(count):
        chunk, length = decode(data[start:])
        # print(i,chunk, length, data[start+length:])
        if chunk is None:  # means the content is not complete or not able to parse.
            return None, None
        start += length
        result.append(chunk)
    return result, start


def parse_chunked(data, start=0):
    index = data.find(DELIMITER, start)
    if index == -1:
        index = start
    length = int(data[start + 1:index])

    if length == -1:  # "$-1\r\n"
        if index + len(DELIMITER) == len(data):
            return "Null Bulk String", len(data)
        else:
            return "Null Bulk String", index + len(DELIMITER)
    else:
        result = data[index + len(DELIMITER):index + len(DELIMITER) + length]
        # print(f'inside redis_protocol {start} content: {len(result)}--- length: {length}')
        if length != len(result):
            if start == 0:
                # return None
                return None, None
            else:
                return [False, False]  # i don't understand this coee
        # return [result] if start == 0 else [result, index + len(DELIMITER) + length]
        # b'$2\r\nOK\r\n'
        return [result, index + len(DELIMITER) + length + len(DELIMITER)]


def parse_status(data):
    """
    simple string b'+string\r\n'
    """
    return data[1:].strip(), len(data)


def parse_error(data):
    """
    error b'$-1\r\n$1\r\n1\r\n'
    we won't parse the detail error, just return it as a strings
    """
    return data[1:].strip(), len(data)


def parse_integer(data):
    index = data.find(DELIMITER)
    if index == -1:
        return None, len(data)

    result = data[1:index]

    return result, index + len(DELIMITER)


if __name__ == '__main__':
    # print(decode(encode("ping")))
    # print((encode("set some value")))
    # print(encode("foobar"))
    # print(parse_stream(data))
    # data = b'+OK\r\n'
    # print(decode(data.decode()))
    # data = b'$-1\r\n'
    # data = b'$262144\r\n'
    # data = b'+OK\r\n'
    # data = b'$-1\r\n$1\r\n1\r\n'
    # data = b'$-1\r\n'
    data = b'$0\r\n\r\n'
    print(f'len of data :{len(data)}')
    print(decode(data))
 
