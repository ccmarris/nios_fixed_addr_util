#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Can be used to Generate a simple report on stale fixed addresses

 Requirements:
   Python 3.8+

 Author: Chris Marrison

 Date Last Updated: 20240205

 Todo:

 Copyright (c) 2024 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

'''
__version__ = '0.1.2'
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD'

import logging
import requests
import argparse
import configparser
import datetime
import time
from rich import print

def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    description = 'NIOS Fixed Address Utility'
    parse = argparse.ArgumentParser(description=description)
    parse.add_argument('-c', '--config', type=str, default='gm.ini',
                        help="Override ini file")
    parse.add_argument('-f', '--filter', type=str, default="all",
                        help="Filter report by type [ all, True, False, Reserved, Unknown ]")
    parse.add_argument('-u', '--update', action='store_true', 
                        help="Update fixed address object in NIOS")
    parse.add_argument('-e', '--ea', type=str, default='',
                        help='Name of EA to use (type STRING)')
    parse.add_argument('-a', '--auto', action='store_true',
                        help='Auto create EA if it does not exist')
    parse.add_argument('-d', '--debug', action='store_true', 
                        help="Enable debug messages")

    return parse.parse_args()


def read_ini(ini_filename):
    '''
    Open and parse ini file

    Parameters:
        ini_filename (str): name of inifile

    Returns:
        config :(dict): Dictionary of BloxOne configuration elements

    '''
    # Local Variables
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = ['gm', 'api_version', 'valid_cert', 'user', 'pass' ]

    # Attempt to read api_key from ini file
    try:
        cfg.read(ini_filename)
    except configparser.Error as err:
        logging.error(err)

    # Look for NIOS section
    if 'NIOS' in cfg.keys():
        for key in ini_keys:
            # Check for key in BloxOne section
            if key in cfg['NIOS']:
                config[key] = cfg['NIOS'][key].strip("'\"")
                logging.debug('Key {} found in {}: {}'.format(key, ini_filename, config[key]))
            else:
                logging.warning('Key {} not found in NIOS section.'.format(key))
                config[key] = ''
    else:
        logging.warning('No NIOS Section in config file: {}'.format(ini_filename))
        config['api_key'] = ''

    return config


def setup_logging(debug):
    '''
     Set up logging

     Parameters:
        debug (bool): True or False.

     Returns:
        None.

    '''
    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


def create_session(user: str = '',
                   passwd: str ='',
                   validate_cert: bool =False):
    '''
    Create request session

    Parameters:
    
    Return:
        wapi_session (obj): request session object
    '''
    headers = { 'content-type': "application/json" }

    # Avoid error due to a self-signed cert.
    if not validate_cert:
        requests.packages.urllib3.disable_warnings()
    
    wapi_session = requests.session()
    wapi_session.auth = (user, passwd)
    wapi_session.verify = validate_cert
    wapi_session.headers = headers

    return wapi_session


class FIXEDADDR:
    '''
    Fixed Address Utility Class
    '''

    def __init__(self, cfg: str = 'gm.ini', 
                 use_eas: bool = False,
                 ea_name: str = 'faddr_in_use',
                 auto_create_ea: bool = False) -> None:
        '''
        Handle Zone Locks

        Parameters:
            cfg_file (str): Override default ini filename
        '''
        self.config = {}
        self.config = read_ini(cfg)
        self.use_eas = use_eas
        self.ea_name = ea_name

        self.gm = self.config.get('gm')
        self.wapi_version = self.config.get('api_version')
        self.username = self.config.get('user')
        self.password = self.config.get('pass')
        self.base_url = f'https://{self.gm}/wapi/{self.wapi_version}'
        self.fixedaddr = []

        if self.config.get('valid_cert') == 'true':
            self.validate_cert = True
        else:
            self.validate_cert = False

        self.session = create_session( user=self.username,
                                      passwd=self.password,
                                      validate_cert=self.validate_cert)

        return
 

    def _add_params(self, url, first_param=True, **params):
        # Add params to API call URL
        if len(params):
            for param in params.keys():
               if first_param:
                   url = url + '?'
                   first_param = False
               else:
                   url = url + '&'
               url = url + param + '=' + params[param]
        
        return url


    def wapi_get(self, **params):
        '''
        Make wapi call

        Parameters:
            **params: parameters for request.get
        
        Returns:
            data: JSON response as object (list/dict) or None
        '''
        status_codes_ok = [ 200, 201 ]

        response = self.session.get(**params)
        if response.status_code in status_codes_ok:
            data = response.json()
        else:
            logging.error(f'HTTP response: {response.status_code}')
            logging.debug(f'Body: {response.content}')
            data = None

        return data


    def wapi_post(self, **params):
        '''
        Make wapi call

        Parameters:
            **params: parameters for request.post
        
        Returns:
            data: JSON response as object (list/dict) or None
        '''
        status_codes_ok = [ 200, 201 ]

        response = self.session.post(**params)
        if response.status_code in status_codes_ok:
            data = response.text
        else:
            logging.error(f'wapi_post failed: {response.status_code}, {response.content}')
            logging.debug(f'HTTP response: {response.status_code}')
            logging.debug(f'Body: {response.content}')
            data = None

        return data


    def wapi_put(self, **params):
        '''
        Make wapi call

        Parameters:
            **params: parameters for request.put
        
        Returns:
            data: JSON response as object (list/dict) or None
        '''
        status_codes_ok = [ 200, 201 ]

        response = self.session.put(**params)
        if response.status_code in status_codes_ok:
            data = response.text
        else:
            logging.error(f'wapi_post failed: {response.status_code}, {response.content}')
            logging.debug(f'HTTP response: {response.status_code}')
            logging.debug(f'Body: {response.content}')
            data = None

        return data


    def check_ea(self) -> bool:
        '''
        Check whether ea exists
        '''
        exists = False
        url = f'{self.base_url}/extensibleattributedef?name={self.ea_name}'
        response = self.wapi_get(url=url)
        if response:
            logging.debug(f'EA {self.ea_name} exists')
            exists = True
        else:
            if self.auto_create_ea:
                logging.debug(f'Auto creating EA: {self.ea_name}')
                if self.create_ea():
                    logging.debug(f'EA: {self.ea_name} created')
                    exists = True
                else:
                    logging.error(f'Failed to auto create EA: {self.ea_name}')
                    exists = False
            else:
                logging.debug(f'EA {self.ea_name} does not exist')
                exists = False
        
        return exists
    
    
    def create_ea(self):
        '''
        Create EA
        '''
        body: dict = {'name': self.ea_name, 'type': 'STRING'}
        url: str = f'{self.base_url}/extensibleattributedef'
        status_codes_ok: list = [ 200, 201 ]
        status: bool = False

        response = self.wapi_post(url=url, json=body)
        if response.status_code in status_codes_ok:
            status = True
        else:
            logging.error(f'wapi_post failed: {response.status_code}, {response.content}')
            logging.debug(f'HTTP response: {response.status_code}')
            logging.debug(f'Body: {response.content}')
            status = False
        
        return status


    def get_fixedaddrs(self, next_page: str ='', **params) -> list:
        '''
        Get list of fixed addresses

        Parameters:

        Returns:
            List of fixed address objects
        '''
        faddr = []
        page_err = False
        return_fields = ( '_return_fields=match_client,ipv4addr,mac,' +
                          'dhcp_client_identifier,network,network_view,' +
                          'agent_circuit_id,agent_remote_id,extattrs' )
        paging = '_paging=1&_max_results=999&_return_as_object=1'

        # Get Zones
        url = f'{self.base_url}/fixedaddress?{return_fields}&{paging}'


        if params:
            url = self._add_params(url, first_param=False, **params)

        # Use base session
        logging.info(f'Retrieving fixed addresses')
        response = self.wapi_get(url=url)
        if response:
            logging.info('Fixed addresses retrieved successfully')
            logging.debug(f'Response: {response}')
            faddr += (response.get('result'))
            next_page = response.get('next_page_id')
            # Page through data
            while next_page:
                logging.debug('Getting next page')
                url = self._add_params(url, first_param=False, _page_id=next_page )
                response = self.wapi_get(url=url)
                if response:
                    logging.info('Next page retrieved successfully')
                    logging.debug(f'Response: {response}')
                    faddr += response.get('result')
                    next_page = response.get('next_page_id')
                else:
                    logging.error('Failed to retrieve page')
                    logging.debug(f'Response: {response}')
                    next_page = None
                    page_err = True
            if not page_err:
                logging.debug('Complete: no more data pages.')
            else:
                logging.info('Error Occured: Returning retrieved fixed addresses')

        else:
            logging.error('Failed to retrieve fixed addresse')
            faddr = []
        
        self.fixedaddr = faddr
        
        return self.fixedaddr


    def get_lease_info(self, ip='', **params):
        '''
        '''
        return_fields = '_return_fields=address,binding_state,hardware,cltt,ends,served_by'
        url = f'{self.base_url}/lease?{return_fields}&address={ip}'

        if params:
            url = self._add_params(url, first_param=False, **params)

        # Use base session
        logging.info(f'Retrieving leases')
        response = self.wapi_get(url=url)
        if response:
            logging.info('Lease retrieved successfully')
            logging.debug(f'Response: {response}')
        else:
            logging.info(f'No lease for IP: {ip} or failed to retrieve')

        return response
    

    def check_in_use(self, days: int = 30) -> list:
        '''
        Check whether fixed address was used in last n days

        Parameters:
            days: int - number of days to be considered in use
                Returns:

            updated list of fixed addresses
        '''
        faddr: list = []
        in_use: bool = False
        cltt: str = ''

        # Check whether we have the fixed addresses
        if not self.fixedaddr:
            self.get_fixedaddrs()
        
        # Re-check
        if self.fixedaddr:
            for fa in self.fixedaddr:
                # Check match_client type
                match_client = fa.get('match_client')
                if match_client == 'RESERVED':
                    in_use = 'Reserved'
                elif match_client == 'MAC_ADDRESS':
                    # Check mac address matches hardware
                    ip = fa.get('ipv4addr')
                    mac = fa.get('mac')
                    logging.info(f'Checking lease data for: {ip}, {mac}')
                    leases = self.get_lease_info(ip=ip)
                    if leases:
                        logging.debug(f'Lease data: {leases}')
                        for l in leases:
                            if mac == l.get('hardware'):
                                cltt = l.get('cltt')
                            
                                if cltt:
                                    # Check timestamp
                                    if self.check_timestamp(timestamp=cltt, days=days):
                                        in_use = 'True'
                                        break
                                    else:
                                        in_use = 'False'
                                    logging.debug(f'IP: {ip}, Used: {in_use}')
                                else:
                                    # No CLTT found
                                    in_use = 'False'
                                    logging.debug(f'No CLTT for IP: {ip}, Used: {in_use}')
                    else:
                        # No lease found
                        in_use = 'Unknown'
                        logging.debug(f'No leases found for IP: {ip}, Used: {in_use}')
                else:
                    # Just check for a CLTT
                    ip = fa.get('ipv4addr')
                    logging.info(f'Checking lease data for: {ip}')
                    leases = self.get_lease_info(ip=ip)
                    if leases:
                        logging.debug(f'Lease data: {leases}')
                        for l in leases:
                            cltt = l.get('cltt')
                            # Can't seem to find client_id in lease object 
                            # so just look for a CLTT
                            if cltt:
                                # Check timestamp
                                if self.check_timestamp(timestamp=cltt, days=days):
                                    in_use = 'True'
                                    break
                                else:
                                    in_use = 'False'
                                logging.debug(f'IP: {ip}, Used: {in_use}')
                            else:
                                # No CLTT found
                                in_use = 'False'
                                logging.debug(f'No CLTT for IP: {ip}, Used: {in_use}')
                    else:
                        # No lease found
                        in_use = 'Unknown'
                        logging.debug(f'No lease for IP: {ip}, Used: {in_use}')


                # Add attribute to object and store
                faddr.append(self.update_fixed_addr(faddr=fa, in_use=in_use))

            # Update attribute
            self.fixedaddr = faddr

        return faddr


    def check_timestamp(self, timestamp: str = '', 
                        days:int = 30):
        '''
        Compare timestamp to now - n days
        
        Parameters:
            timestamp: str = Timestamp to compare
            days: int = Number of days to compare
        
        Returns:
            bool
        '''
        status: bool = False
        now = datetime.datetime.now()
        delta = now - datetime.timedelta(days=days)

        if datetime.datetime.fromtimestamp(int(timestamp)) > delta:
            status = True
        else:
            status = False

        return status


    def update_fixed_addr(self, faddr: dict = {}, in_use: str = 'Unknown') -> dict:
        '''
        Update the fixed address object with EA indicating use status
        If the use_eas flag is set the this will write the update to NIOS

        Parameters:
            faddr: dict = fixedaddress object
            in_use: bool = Flag

        Returns:
            Fixed address data object
        '''
        ref: str = ''
        url: str = ''
        
        if faddr:
            # Add or update extensible attribute
            faddr['extattrs'].update({self.ea_name: {"value": str(in_use)}})

            # Check whether we update NIOS
            if self.use_eas:
                if check_ea():
                    logging.info(f'Updating fixed address: {faddr.get('ipv4addr')}')
                    if self.modify_fixed_addr(obj=faddr):
                        logging.info(f'Successfully updated: {faddr.get('ipv4addr')}')
                    else:
                        logging.error(f'Failed to update: {faddr.get('ipv4addr')}')
                else:
                    logging.error(f'Extensible Attribute: {self.ea_name} does not exist')

        return faddr


    def modify_fixed_addr(self, obj: dict = {}) -> bool:
        '''
        '''
        status: bool = False
        url: str = ''

        if obj:
            data =obj.copy()
            ref = data.get('_ref')
            logging.info(f'Updating object: {ref}')
            url = f'{self.base_url}/{ref}'
            response = self.wapi_put(url=url, json=data)
            if response:
                logging.info(f'Successfully updated: {ref}')
                status = True
            else:
                logging.info(f'Failed to update: {ref}')
                logging.error(f'URL: {url}, Object: {data}')
                status = False
        
        return status


    def retrieve_use(self, obj: dict = {}) -> str:
        '''
        Retrieve the use from the ea_name as a string
        '''
        eas: dict = {}
        ea: dict = {}
        use: str = ''

        eas = obj.get('extattrs')
        if eas:
            ea = eas.get(self.ea_name)
            if ea:
                # Return ea's value
                use = ea.get('value')
            else:
                # Return empty string
                use = ''
        else:
            # Return empty string
            use = ''
        
        return use


    def report(self, match_use: str = 'all'):
        '''
        Simple Report

        Parameters:
            match_use: str = Use type to report on or all
        '''
        line: str = ''
        use: str = ''
        header: list = [ 'IP', 
                        'match_client', 
                        'mac', 
                        'dhcp_client_identifier', 
                        self.ea_name ]
        


        print(f'{header}')
        for fa in self.fixedaddr:
            line = ''
            use = self.retrieve_use(fa)

            if use == match_use or match_use == 'all':
                line = [ fa.get('ipv4addr'),
                        fa.get('match_client'),
                        fa.get('mac'),
                        fa.get('dhcp_client_identifier'),
                        use ]
                
                print(f'{line}')
    
        return
    

def main():
    '''
    Code logic
    '''
    exitcode = 0
    run_time = 0

    # Parse CLI arguments
    args = parseargs()
    setup_logging(args.debug)

    t1 = time.perf_counter()

    FixedAddr = FIXEDADDR(cfg=args.config,
                          use_eas=args.update,
                          ea_name=args.ea,
                          auto_create_ea=args.auto)
    
    # Populate the fixed addresses
    FixedAddr.get_fixedaddrs()
    # Check status of fixed addresses
    FixedAddr.check_in_use()
    # Output Report
    FixedAddr.report(match_use=args.filter)

    run_time = time.perf_counter() - t1
    
    logging.info('Run time: {}'.format(run_time))

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
## End Main ###
