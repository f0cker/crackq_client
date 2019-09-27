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
import re
from requests import Session
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth

if sys.version_info.major < 3:
    print('Crackq_client requires Python version 3')
    exit(1)
from pathlib import Path

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

    def sso_login(self, user=None, passwd=None,
                  atype=None, url=None, mfa=True):
        """SAML2 SSO Login"""
        if not url:
            url = self.url + '/api/sso'
        if user and passwd:
            if atype == 'forms':
                data_dict = {
                    'UserName': user,
                    'Password': passwd,
                    'AuthMethod': 'FormsAuthentication',
                }
                req1 = self.sess.post(url,
                                      data=data_dict,
                                      proxies=self.proxy,
                                      headers=self.headers,
                                      verify=self.verify)
            elif atype == 'ntlm':
                self.sess.auth = HttpNtlmAuth(user, passwd)
        else:
            return self.sess.get(url,
                                 proxies=self.proxy,
                                 headers=self.headers,
                                 verify=self.verify)
        if mfa and '302' in str(req1.history):
            print('Login OK. Starting MFA...')
            data_dict2 = {}
            if req1.status_code == 200:
                req1_soup = BeautifulSoup(req1.text, "lxml")
                for input_tag in req1_soup.find_all(re.compile('input')):
                    name = input_tag.get('name', '')
                    value = input_tag.get('value', '')
                    data_dict2[name] = value
            else:
                logger.warning('Login Error: {}'.format(req1.status_code))

            data_dict2['AuthMethod'] = 'AzureMfaServerAuthentication'
            mfa_url = req1.url
            print('Waiting for MFA...')
            req2 = self.sess.post(mfa_url,
                                  proxies=self.proxy,
                                  data=data_dict2,
                                  verify=self.verify)
            mfa_soup2 = BeautifulSoup(req2.text, "lxml")
            data_dict3 = {}
            for input_tag in mfa_soup2.find_all(re.compile('input')):
                name = input_tag.get('name', '')
                value = input_tag.get('value', '')
                data_dict3[name] = value

            data_dict3['AuthMethod'] = 'AzureMfaServerAuthentication'
            req3 = self.sess.post(mfa_url,
                                  proxies=self.proxy,
                                  data=data_dict3,
                                  verify=self.verify)
            req3_soup = BeautifulSoup(req3.text, 'lxml')
            saml_resp = None
            for input_tag in req3_soup.find_all(re.compile('input')):
                if input_tag.get('name') == 'SAMLResponse':
                    saml_resp = input_tag.get('value')
                    login_url = self.url + '/api/sso'
            if saml_resp:
                data_dict4 = {
                    'SAMLResponse': saml_resp,
                }
                req4 = self.sess.post(login_url,
                                      proxies=self.proxy,
                                      data=data_dict4,
                                      allow_redirects=False,
                                      headers=self.headers,
                                      verify=self.verify)
                return req4
            else:
                return 'Error'
        elif not mfa and '302' in str(req1.history):
            ###***this needs testing against a server with no mfa
            return req1
        else:
            return 'Error'

    def logout(self):
        """Logout"""
        return self.sess.get(self.url + '/api/logout',
                             proxies=self.proxy,
                             headers=self.headers,
                             verify=self.verify)
