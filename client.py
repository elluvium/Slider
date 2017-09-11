#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import urllib
import re
import os
import sys
import hashlib
import bz2
import logging
from optparse import OptionParser

IPv4_REGEXP = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
CHUNKS_DIR = '/tmp/chunks/'


logging.basicConfig(filename='client.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')
parser = OptionParser()
parser.add_option('-s', '--source', dest='if_dir',
                  help='source directory')
parser.add_option('-d', '--destination', dest='of_dir',
                  help='destination directory')
parser.add_option('-i', '--address', dest='server_ip',
                  help='server ip')

options, args = parser.parse_args()

IF_DIR = str(options.if_dir)
OF_DIR = str(options.of_dir)
server_ip = str(options.server_ip)
volume_file_name = OF_DIR + 'volume' if OF_DIR[-1] == '/' else OF_DIR + '/volume'
BLOCK_SIZE = 16384
DESCRIPTION = OF_DIR + 'description' if OF_DIR[-1] == '/' else OF_DIR + '/description'

nginx_port = '80'
description = {}


def stop_script(error):
    logging.info('It seems you have the next error:')
    logging.error('{}'.format(error))
    sys.exit()


def ip_check(ip):
    if not re.match(IPv4_REGEXP, ip):
        stop_script("Looks like you entered a wrong IPv4 address")
    return True


def start_request(ip, port, data):
    ip_check(ip)
    uri = ip + ":" + port + data
    urllib.urlretrieve('http://' + uri, DESCRIPTION)
    logging.info("Trying to connect to: {0}:{1}, downloading file {2}".format(ip, port, data.split('/')[-1]))
    parse_description(DESCRIPTION)


def parse_description(desc):
    logging.info("parsing description file")
    with open(desc, 'r') as data:
        content = data.readlines()
    for x in range(len(content)):
        description[x] = content[x].strip()
    logging.debug(description)
    print(description)
    logging.info("description file saved at {}".format(DESCRIPTION))
    print("description file saved at {}".format(DESCRIPTION))


def chunks_mount(chunk, volume_name, i, block_size):
    os.system('dd if={0} of={1} seek={2} bs={3} count=1'.format(CHUNKS_DIR + chunk, volume_name, i, block_size * 1024))


def download_chunk(ip, port, chunk_location, number):
    uri = ip + ":" + port + chunk_location
    urllib.urlretrieve('http://' + uri + '.bz2', '{}/slider-chunk-{}.bz2'.format(CHUNKS_DIR, number))
    urllib.urlretrieve('http://' + uri + '.md5', '{}/slider-chunk-{}.md5'.format(CHUNKS_DIR, number))
    print("Trying to connect to: {0}:{1}, downloading file {2}".format(ip, port, chunk_location.split('/')[-1]))


def disk_space_analyzer(path, disk_space):
    stat = os.statvfs(path)
    free_space_kb = (stat.f_bfree * stat.f_bsize) / 1024
    if free_space_kb <= int(disk_space):
        stop_script("Not enough space. Free space: {0} kb but needed {1}".format(free_space_kb, disk_space))
    else:
        return True


def md5_generate(chunk):
    print("Checking md5 for " + chunk)
    logging.info("Checking md5 for " + chunk)
    checksum_md5 = hashlib.md5()
    with open('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(chunk)), 'rb') as data:
        for chunk_part in iter(lambda: data.read(4096), b""):
            checksum_md5.update(chunk_part)
        current_md5 = '{}{}'.format(CHUNKS_DIR, '{}.md5'.format(chunk))
    with open(current_md5, 'r') as md5:
        if checksum_md5.hexdigest() != md5.readline():
            return False
        else:
            return True


def request_for_chunk(number):
    sock.send(str(number))
    chunk_data = sock.recv(1024)
    download_chunk(server_ip, nginx_port, chunk_data, number)
    return chunk_data.split('/')[-1]


def extract(chunk):
    print("Start decompression for " + chunk)
    logging.info("Start decompression for " + chunk)
    with open('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(chunk)), 'rb') as archive:
        content = archive.read()
        decompress_data = bz2.decompress(content)
    with open('{}{}'.format(CHUNKS_DIR, chunk), 'wb') as part:
        part.write(decompress_data)


def remove_chunks(name):
    os.remove('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(name)))
    os.remove('{}{}'.format(CHUNKS_DIR, '{}.md5'.format(name)))


def main():
    if not os.path.exists(CHUNKS_DIR):
        os.mkdir(CHUNKS_DIR)

    global sock
    sock = socket.socket()
    ip_check(server_ip)
    sock.connect((server_ip, 8090))
    sock.send(IF_DIR)
    data = sock.recv(1024)
    start_request(server_ip, nginx_port, data)
    disk_space_analyzer(OF_DIR, description[0])
    for numb in range(int(description[1])):
        print('downloading chunks: {} / {} '.format(numb + 1, description[1]))
        logging.info('downloading chunks: {} / {} '.format(numb + 1, description[1]))
        chunk_name = request_for_chunk(numb)
        max_retries = 5
        for retry in range(max_retries):
            if md5_generate(chunk_name):
                extract(chunk_name)
                chunks_mount(chunk_name, volume_file_name, numb, BLOCK_SIZE)
                remove_chunks(chunk_name)
                os.remove('{}{}'.format(CHUNKS_DIR, chunk_name))
                break
            elif not md5_generate(chunk_name) and retry == max_retries - 1:
                remove_chunks(chunk_name)
                stop_script("Seems like it's failed to download chunk with correct md5")
            else:
                logging.info("{0}th attempt downloading {1}".format(retry, chunk_name))
                remove_chunks(chunk_name)
                request_for_chunk(numb)
    print("Sliding finished!")
    sock.send('finish')
    logging.info("Sliding finished!")


if __name__ == "__main__":
    main()
