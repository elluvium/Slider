#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket, urllib, re, os, sys, datetime, hashlib, bz2
import logging
from optparse import OptionParser

IPv4_REGEXP = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
CHUNKS_DIR = '/tmp/chunks/'
#DC_DIR = '/tmp/chunks'

logging.basicConfig(filename='client.log',level=logging.INFO,
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
DESCRIPTION = OF_DIR + 'description' if OF_DIR[-1] == '/' else OF_DIR + '/description'

nginx_port = '80'
description = {}

def stop_script(error):
    logging.info('It seems you have the next error:')
    logging.error('{}'.format(error))
    '''
    print("It seems you have the next error:")
    print("{0}-[ERROR]--{1}".format(datetime.datetime.now(), error))
    sys.exit()
    '''

def start_request(ip, nginx_port, data):
    #    if not re.match(IPv4_REGEXP, ip):
    #        print("Looks like you entered a wrong IPv4 address")
    #        exit(1)
    uri = ip + ":" + nginx_port + data
    urllib.urlretrieve('http://' + uri, DESCRIPTION)
    logging.info("Trying to connect to: {0}:{1}, downloading file {2}".format(ip, nginx_port, data.split('/')[-1]))
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
#    if get_request.status_code == 200:
#        with open(description_file_path, 'wb') as file:
#            file.write(get_request.content)
#        print("YAY! Description file has been successfully downloaded!")
#    else:
#        stop_script("OOPS! Check this error HTTP {0}".format(get_request.status_code))

def download_chunk(ip, nginx_port, addres_tochunk, number):
    uri = ip + ":" + nginx_port + addres_tochunk
    urllib.urlretrieve('http://' + uri + '.bz2', '{}/slider-chunk-{}.bz2'.format(CHUNKS_DIR, number))
    urllib.urlretrieve('http://' + uri + '.md5', '{}/slider-chunk-{}.md5'.format(CHUNKS_DIR, number))
    print("Trying to connect to: {0}:{1}, downloading file {2}".format(ip, nginx_port, addres_tochunk.split('/')[-1]))


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
    print("Start decompession for " + chunk)
    logging.info("Start decompession for " + chunk)
    with open('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(chunk)), 'rb') as archive:
        content = archive.read()
        decomperess_data = bz2.decompress(content)
    with open('{}{}'.format(CHUNKS_DIR, chunk), 'wb') as part:
        part.write(decomperess_data)


def main():
    if not os.path.exists(CHUNKS_DIR):
        os.mkdir(CHUNKS_DIR)

    global sock
    sock = socket.socket()
    sock.connect((server_ip, 8090))
    sock.send(IF_DIR)
    data = sock.recv(1024)
    start_request(server_ip, nginx_port, data)
    disk_space_analyzer(OF_DIR, description[0])
    for numb in range(int(description[1])): #int(description[1])
        print('downloading chunks: {} / {} '.format(numb + 1, description[1]))
        logging.info('downloading chunks: {} / {} '.format(numb + 1, description[1]))
        chunk_name = request_for_chunk(numb)
        #chunk_name = chunk_data.split('/')[-1]
        max_retries = 5
        for retr in range(max_retries):
            if md5_generate(chunk_name):
                #-------------------------------------------Send response here--------------------------------
                #sock.send("success")
                break;
            elif not md5_generate(chunk_name) and retr == 4:
                os.remove('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(chunk_name)))
                os.remove('{}{}'.format(CHUNKS_DIR, '{}.md5'.format(chunk_name)))
                stop_script("Seems like it's failed to download chunk with correct md5")
            else:
                logging.info("Another attempt to download chunk")
                os.remove('{}{}'.format(CHUNKS_DIR, '{}.bz2'.format(chunk_name)))
                os.remove('{}{}'.format(CHUNKS_DIR, '{}.md5'.format(chunk_name)))
                request_for_chunk(numb)
        extract(chunk_name)
    print("Sliding finished!")
    logging.info("Sliding finished!")



if __name__ == "__main__":
    main()