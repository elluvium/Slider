#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import time
import os
import bz2
import hashlib
import re
from optparse import OptionParser

# parser = OptionParser()
# parser.add_option('-t', '--start', dest='state', action='store_true',
#                   help='start as a daemon')
# parser.add_option('-s', '--stop', dest='state', action='store_false',
#                   help='stop this daemon')
# parser.add_option('-n', '--no-daemonize', dest='daemon', action='store_true',
#                   help='start as a daemon')
# options, args = parser.parse_args()

NGINX_TRANSFER_DIR = '/usr/share/nginx/html/slider'
DESCRIPTION = NGINX_TRANSFER_DIR+'/description'
block_size = 16384
CHUNK_NAME = 'slider-chunk'
OF_DIR = '/tmp/chunks'

def main():
    if not os.path.exists(OF_DIR):
        if not os.path.exists(NGINX_TRANSFER_DIR):
            os.mkdir(OF_DIR)
            os.mkdir(NGINX_TRANSFER_DIR)
        else:
            os.mkdir(OF_DIR)
    else:
        if not os.path.exists(NGINX_TRANSFER_DIR):
            os.mkdir(NGINX_TRANSFER_DIR)
        else:
            pass
    global disk_len
    global chunks_num
    global IF_DIR
    servsoc = socket.socket()
    servsoc.bind(('', 8090))
    servsoc.listen(1)
    conn, addr = servsoc.accept()
    while True:
        data = conn.recv(2048)
        if not data:
            break
        elif re.compile('(?:[^/]*/.*)').match(data): # e.g. /dev/sda2
            IF_DIR = data
            os.system('df | grep {} '.format(data) + '| awk \'{print $2}\' > ' + DESCRIPTION)
            with open(DESCRIPTION, 'r+w') as description:
                disk_len = int(description.readline())
                chunks_num = (disk_len / block_size) + 1
                description.write(str(chunks_num) + '\n')
            conn.send('/slider/description')
        elif re.compile('(^[0-9]+)').match(data):
            chunk_create(data)
            conn.send('/slider/{0}-{1}'.format(CHUNK_NAME, data))
        elif re.compile('(^[0-9]+)').match(str(data).split('-')[-1]):
            clear_transfered(str(data).split('-')[-1])
        #conn.close()

def compress_chunks(chunk, i):
    compressed_chunk = bz2.compress(bytes(chunk.encode('utf-8')))
    chunk_ar_name = '{0}-{1}'.format(CHUNK_NAME, str(i))
    with open('{0}/{1}.bz2'.format(NGINX_TRANSFER_DIR, chunk_ar_name), 'wb') as flow:
        flow.write(compressed_chunk)
    chunk_ar_name += '.bz2'
    return chunk_ar_name, count_checksum(chunk_ar_name)

def count_checksum(chunk_archive):
    md5_checksum = hashlib.md5()
    with open('{0}/{1}'.format(NGINX_TRANSFER_DIR, chunk_archive), 'rb') as data:
        for chunk in iter(lambda: data.read(4096), b""):
            md5_checksum.update(chunk)
    with open('{0}/{1}.md5'.format(NGINX_TRANSFER_DIR, chunk_archive.split('.')[0]), 'w') as flow:
        flow.write(md5_checksum.hexdigest())

def chunk_create(i):
    chunk = '{0}/{1}-{2}'.format(OF_DIR, CHUNK_NAME, i)
    os.system('dd if={} '.format(IF_DIR) + 'of={} '.format(chunk) + 'skip={} '.format(i)
              + 'bs={} '.format(block_size*1024) + 'count=1')
    compress_chunks(chunk, i)

def clear_transfered(i):
    chunk = '{0}/{1}-{2}'.format(OF_DIR, CHUNK_NAME, i)
    compressed_chunk = '{0}/{1}-{2}.bz2'.format(NGINX_TRANSFER_DIR, CHUNK_NAME, i)
    chunk_checksum = '{0}/{1}-{2}.md5'.format(NGINX_TRANSFER_DIR, CHUNK_NAME, i)
    to_delete = [chunk, compressed_chunk, chunk_checksum]
    for file in to_delete:
        os.remove('{}'.format(file))

if __name__ == "__main__":
    main()

