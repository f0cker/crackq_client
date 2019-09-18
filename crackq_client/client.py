# -*- coding: utf-8 -*-

"""
Python client for interacting with CrackQ REST API.

A queuing system for multi-user hash cracking using Hashcat.

Author: dturner@trustwave (@f0cker_)
"""

import argparse
import getpass
import json
import os
import logging
import pprint
import sys
import crackq_client.client_rest as client_rest

if sys.version_info.major < 3:
    print('Crackqcli requires Python version 3')
    exit(1)

from pathlib import Path

os.umask(0o077)

BANNER = '''
                   _/_/_/                                _/          _/_/
                _/        _/  _/_/    _/_/_/    _/_/_/  _/  _/    _/    _/
               _/        _/_/      _/    _/  _/        _/_/      _/  _/_/
              _/        _/        _/    _/  _/        _/  _/    _/    _/
               _/_/_/  _/          _/_/_/    _/_/_/  _/    _/    _/_/  _/'''
print(u'\u001b[31m {} \u001b[0m'.format(BANNER))


def set_logger(level):
    """
    Simple logging setup

    Arguments
    ---------
    level: logging.level
        Logging level of type logging.level

    Returns
    -------
    logger: obj
        logging object use for log output
    """
    log = logging.getLogger(__name__)
    log.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(levelname)-8s %(asctime)-8s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

logger = set_logger(logging.INFO)


def parse_args():
    """
    Arg parsing
    """
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     argument_default=None, usage="%(prog)s ")
    mut_group = parser.add_mutually_exclusive_group(required=True)
    api_group = parser.add_argument_group('API arguments')
    api_group.add_argument_group(mut_group)
    hc_group = parser.add_argument_group('Hashcat arguments')
    misc_group = parser.add_argument_group('Miscellaneous arguments')
    mut_group.add_argument('-l', '--login', default=False, action='store_true',
                           help='Login and receive token')
    mut_group.add_argument('-L', '--logout', default=False, action='store_true',
                           help='Logout current session')
    mut_group.add_argument('-a', '--add', default=False, action='store_true',
                           help='Add job')
    mut_group.add_argument('-d', '--delete', default=False, action='store_true',
                           help='Delete job and totally remove all trace')
    mut_group.add_argument('-s', '--stop', default=False, action='store_true',
                           help='Stop job and move to complete queue')
    mut_group.add_argument('-f', '--failed', default=False, action='store_true',
                           help='Get failed jobs')
    mut_group.add_argument('-r', '--restore', default=False, action='store_true',
                           help='Resotre selected job, re-adding to queue using'
                                ' the stored restore point if there is one')
    mut_group.add_argument('-j', '--job', default=False, action='store_true',
                           help='Get job details')
    mut_group.add_argument('-p', '--pause', default=False, action='store_true',
                           help='Pause selected job')
    mut_group.add_argument('-c', '--complete', default=False, action='store_true',
                           help='Get list of completed jobs')
    mut_group.add_argument('-m', '--mov', default=False, action='store_true',
                           help='Move job')
    mut_group.add_argument('-q', '--queue', default=False, action='store_true',
                           help='Retrieve current queue state')
    mut_group.add_argument('-o', '--options', default=False, action='store_true',
                           help='Retrieve available options (wordlists/rules)')
    hc_group.add_argument('--job_id', default=None, type=str,
                          help='Job ID used for queue reference and Hashcat'
                          'session')
    hc_group.add_argument('--attack_mode', default=None, type=int,
                          help='Hashcat attack mode, 0=wordlist/rules,'
                          '2=combinator, 2=, 3=brute force,')
    hc_group.add_argument('--hash_mode', default=None, type=str,
                          help='Hashcat (-m) mode number corresponding to hash '
                          'algorithm')
    hc_group.add_argument('--url', default=None, type=str, required=True,
                          help='URL to use')
    hc_group.add_argument('--hash_file', default=None, type=str,
                          help='File containing list of hashes')
    hc_group.add_argument('--name', default=None, type=str,
                          help='Friendly name for job')
    hc_group.add_argument('--wordlist', default=None, type=str,
                          help='Wordlist name to use for cracking job')
    hc_group.add_argument('--rules', default=None, type=str,
                          help='Rule file name corresponding to list of rules '
                          'stored on the CrackQ server')
    hc_group.add_argument('--mask', default=None, type=str,
                          help='Hashcat mask to use, d=digit, l=lower,'
                          ' u=upper, a=all, s=symbol, e.g. ?a?a?a?a')
    hc_group.add_argument('-u', '--username', default=False,
                          action='store_true', help='Supply hash in format'
                          ' including username (admin:deadbeef)')
    hc_group.add_argument('--disable_brain', default=False,
                          action='store_true', help='Manually disable brain')
    misc_group.add_argument('--user', default='admin', type=str,
                            help='Username to use')
    misc_group.add_argument('--passwd', default=None, type=str,
                            help='Password to use, leave this blank'
                            'to enter securely')
    misc_group.add_argument('--proxy', default=None, type=str,
                            help='Set custom proxy options')
    misc_group.add_argument('--disable_ssl_verify', default=False,
                            action='store_true', help='Disable SSL certificate'
                            'verification. Default is False (which verifies'
                            'the cert)')
    return parser.parse_args()


def main():
    opts = parse_args()
    if opts.disable_ssl_verify:
        verify = False
    else:
        verify = True
    if opts.rules:
        rules = [rule for rule in opts.rules.split(',')]
    else:
        rules = None
    if opts.hash_file:
        try:
            with open(opts.hash_file, 'r') as hash_fh:
                hash_list = [hashl.strip() for hashl in hash_fh]
                query_args = {
                    'mask': opts.mask,
                    'hash_list': hash_list,
                    'wordlist': opts.wordlist,
                    'attack_mode': opts.attack_mode,
                    'hash_mode': opts.hash_mode,
                    'rules': rules,
                    'name': opts.name,
                    'username': opts.username,
                    'disable_brain': opts.disable_brain,
                    'job_id': opts.job_id,
                    }
        except FileNotFoundError as err:
            logger.error('Hash file not found: {}'.format(err))
            exit(1)
        except (IOError, TypeError) as err:
            logger.error('No hash file provided: {}'.format(err))
            exit(1)

    if opts.proxy:
        proxy_dict = {'http': opts.proxy,
                      'https': opts.proxy,
                      }
        client = client_rest.ClientReq(opts.url,
                                       verify=verify,
                                       proxy=proxy_dict)
    else:
        client = client_rest.ClientReq(opts.url,
                                       verify=verify)
    if opts.add:
        if not all([opts.hash_file,
                    str(opts.attack_mode),
                    opts.hash_mode]):
            logger.error('Not enough arguments provided')
            exit(1)
        resp = client.add_job(query_args)
    elif opts.login:
        query_args = {
            'user': opts.user if opts.user else getpass.getpass(
                'Enter Username:'),
            'password': opts.passwd if opts.passwd else getpass.getpass(
                'Enter Password:'),
                }
        resp = client.login(query_args)
        if resp.status_code == 200:
            token = resp.cookies.get_dict()
            token_path = str(Path.home() / '.crackq/token.txt')
            try:
                with open(token_path, 'w') as fh_token:
                    fh_token.write(json.dumps(token))
            except json.decoder.JSONDecodeError:
                logger.error('Auth failed or invalid token returned')
            except FileNotFoundError:
                logger.debug('No token file found')
                Path.mkdir(Path.home() / '.crackq', exist_ok=True)
                with open(token_path, 'w') as fh_token:
                    fh_token.write(json.dumps(token))

    elif opts.logout:
        resp = client.logout()
    elif opts.restore:
        query_args = {
            'job_id': opts.job_id,
            }
        resp = client.add_job(query_args)
    elif opts.delete:
        resp = client.del_job(opts.job_id)
    elif opts.stop:
        resp = client.stop_job(opts.job_id)
    elif opts.mov:
        resp = client.mov_job(opts.job_id)
    elif opts.complete:
        resp = client.q_complete()
    elif opts.failed:
        resp = client.q_failed()
    elif opts.job:
        resp = client.job_details(opts.job_id)
    elif opts.options:
        resp = client.options()
    else:
        resp = client.q_all()
    print('Status: {}'.format(resp.status_code))
    try:
        pprint.pprint(resp.json())
    except json.decoder.JSONDecodeError:
        pass
