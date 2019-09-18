# -*- coding: utf-8 -*-

"""
Python client for interacting with CrackQ REST API.

A queuing system for multi-user hash cracking using Hashcat.

Author: dturner@trustwave (@f0cker_)
"""

import logging
import json
import os
import sys
from pathlib import Path
from requests import Session

os.umask(0o077)


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
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(levelname)-8s %(asctime)-8s %(    message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


class ClientReq():
    """
    This class defines all the different requests that can
    be made to the API
    """
    def __init__(self, url, proxy=None, verify=True):
        logger = set_logger(logging.INFO)
        self.sess = Session()
        self.url = url
        self.proxy = proxy
        self.verify = verify
        self.headers = ''
        try:
            with open(str(Path.home() / '.crackq/token.txt')) as fh_token:
                token = json.loads(fh_token.read())
                for name, value in token.items():
                    self.sess.cookies.set(name, value)
        except FileNotFoundError:
            logger.debug('No token file found')
        except json.decoder.JSONDecodeError:
            logger.debug('Token read error')
        except KeyError:
            logger.debug('Token read error')

    def q_all(self):
        """View current queue"""
        return self.sess.get(self.url + '/api/queuing/all',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def job_details(self, job_id):
        """Get details for specified job ID"""
        return self.sess.get(self.url + '/api/queuing/{:s}'.format(job_id),
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def options(self):
        """View available options (hash modes, wordlists, rules etc)"""
        return self.sess.get(self.url + '/api/options',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    ###***remove/unused??
    def job_pause(self, job_id):
        """Pause job"""
        return self.sess.get(self.url + '/api/queuing/{:s}'.format(job_id),
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def q_failed(self):
        """View failed queue"""
        return self.sess.get(self.url + '/api/queuing/failed',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def q_complete(self):
        """View complete queue"""
        return self.sess.get(self.url + '/api/queuing/complete',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def add_job(self, data_dict):
        """Add a new job. Provide relevant post data as dictionary"""
        return self.sess.post(self.url + '/api/add',
                              json=data_dict,
                              proxies=self.proxy,
                              headers=self.headers,
                              verify=self.verify)

    def del_job(self, job_id):
        "Delete specified job ID"""
        return self.sess.delete(self.url + '/api/queuing/{:s}'.format(job_id),
                                proxies=self.proxy,
                                headers=self.headers,
                                verify=self.verify)

    def stop_job(self, job_id):
        """Stop specified job ID"""
        return self.sess.patch(self.url + '/api/queuing/{:s}'.format(job_id),
                               proxies=self.proxy,
                               headers=self.headers,
                               verify=self.verify)

    ###***Unfinished
    def mov_job(self, job_id):
        """Move specified job ID to specified place in queue"""
        return self.sess.put(self.url + '/api/mov/{:s}/'.format(job_id),
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)

    def login(self, data_dict):
        """Login to API, provide creds via dictionary"""
        return self.sess.post(self.url + '/api/login',
                              json=data_dict,
                              proxies=self.proxy,
                              headers=self.headers,
                              verify=self.verify)

    def logout(self):
        """Logout"""
        return self.sess.get(self.url + '/api/logout',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)
