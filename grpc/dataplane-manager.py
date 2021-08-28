#!/usr/bin/python

# Copyright (c) 2021, WAND Network Research Group
#                     Department of Computer Science
#                     University of Waikato
#                     Hamilton
#                     New Zealand
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330,
# Boston,  MA 02111-1307  USA
#
# @Author : Dimeji Fayomi

import logging 
import time
import json
import grpc
import sys
import os
from pathlib import Path
from pyroute2 import IPRoute
from pyroute2 import NFTables
from google.protobuf import json_format
from utils import validate_ip_address
from utils import get_address_family
import subprocess
from dotenv import load_dotenv
from pkg_resources import resource_filename
from argparse import ArgumentParser
from socket import AF_INET, AF_INET6
from concurrent import futures
import srv6_explicit_path_pb2_grpc
import srv6_explicit_path_pb2
from srv6_manager import SRv6ExplicitPathHandler
from dpserviceapi import DataplaneStateHandler, ConfigureDataplaneHandler
import dataplane_pb2
import dataplaneapi_pb2_grpc



# Logger reference
logger = logging.getLogger("dataplane-manager")
#strHandler = logging.StreamHandler()
#formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
#strHandler.setFormatter(formatter)
#logger.addHandler(strHandler)



# Default path to the .env file
DEFAULT_ENV_FILE_PATH = resource_filename(__name__, './dataplane_manager.env')

def start_server(grpc_ip,grpc_port,
                 secure,certificate,
                 key):

    """Start gRPC server on node"""
    # Get family of the gRPC IP
    addr_family = get_address_family(grpc_ip)
    # Build address depending on the family
    if addr_family == AF_INET:
        # IPv4 address
        server_addr = '%s:%s' % (grpc_ip, grpc_port)
    elif addr_family == AF_INET6:
        # IPv6 address
        server_addr = '[%s]:%s' % (grpc_ip, grpc_port)
    else:
        # Invalid address
        logger.fatal('Invalid gRPC address: %s', grpc_ip)
        sys.exit(-2)
    # Create IP route object for servers 
    iproute = IPRoute()
    # Create the servers and add the handlers
    grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    srv6_explicit_path_pb2_grpc.add_SRv6ExplicitPathServicer_to_server(
        SRv6ExplicitPathHandler(iproute), grpc_server)
    dataplaneapi_pb2_grpc.add_DataplaneStateServicer_to_server(
        DataplaneStateHandler(iproute), grpc_server)
    dataplaneapi_pb2_grpc.add_ConfigureDataplaneServicer_to_server(
        ConfigureDataplaneHandler(iproute), grpc_server)
    
    # If secure we need to create a secure endpoint
    if secure:
        # Read key and certificate
        with open(key, 'rb') as key_file:
            key = key_file.read()
        with open(certificate, 'rb') as certificate_file:
            certificate = certificate_file.read()
        # Create server ssl credentials
        grpc_server_credentials = (grpc
                                   .ssl_server_credentials(((key,
                                                             certificate),)))
        # Create a secure endpoint
        grpc_server.add_secure_port(server_addr, grpc_server_credentials)
    else:
        # Create an insecure endpoint
        grpc_server.add_insecure_port(server_addr)
    # Start the loop for gRPC
    logger.info('*** Listening gRPC on address %s', server_addr)
    grpc_server.start()
    while True:
        time.sleep(5)
    

def parse_arguments():
    """Command-line arguments parser"""

    # Get parser
    parser = ArgumentParser(
        description='gRPC Southbound API for Overwatch SRv6 Controller'
    )
    parser.add_argument(
        '-e', '--env-file', dest='env_file', action='store',
        default=None, help='Path to .env file '
        'containing the parameters for the node manager'
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Activate debug logs'
    )
    args = parser.parse_args()
    return args
    
class Config:
    """Class implementing some configuration parameters and methods
    for the node manager"""

    # pylint: disable=too-many-instance-attributes, too-many-branches
    # pylint: disable=global-statement
    def __init__(self):
        # Flag indicating whether to enable the SRv6 capabilities or not
        #self.enable_srv6_manager = True
        # IP address of the gRPC server (:: means any)
        self.grpc_ip = None
        # Port of the gRPC server
        self.grpc_port = None 
        # Define whether to enable gRPC secure mode or not
        self.grpc_secure = None
        # Path to the certificate of the gRPC server required
        # for the secure mode
        self.grpc_server_certificate_path = None
        # Path to the key of the gRPC server required for the secure mode
        self.grpc_server_key_path = None
        # Define whether to enable the debug mode or not
        self.debug = None
        # Define whether to enable SRv6 PM functionalities or not
        self.enable_srv6_pm_manager = False

    def load_config(self, env_file):
        """Load configuration from a .env file"""

        logger.info('*** Loading configuration from %s', env_file)
        # Path to the .env file
        env_path = Path(env_file)
        # Load environment variables from .env file
        load_dotenv(dotenv_path=env_path)
        # IP address of the gRPC server (:: means any)
        if os.getenv('GRPC_IP') is not None:
            self.grpc_ip = os.getenv('GRPC_IP')
        # Port of the gRPC server
        if os.getenv('GRPC_PORT') is not None:
            self.grpc_port = int(os.getenv('GRPC_PORT'))
        # Define whether to enable gRPC secure mode or not
        if os.getenv('GRPC_SECURE') is not None:
            self.grpc_secure = os.getenv('GRPC_SECURE')
            # Values provided in .env files are returned as strings
            # We need to convert them to bool
            if self.grpc_secure.lower() == 'true':
                self.grpc_secure = True
            elif self.grpc_secure.lower() == 'false':
                self.grpc_secure = False
            else:
                # Invalid value for this parameter
                self.grpc_secure = None
        # Path to the certificate of the gRPC server required
        # for the secure mode
        if os.getenv('GRPC_SERVER_CERTIFICATE_PATH') is not None:
            self.grpc_server_certificate_path = \
                os.getenv('GRPC_SERVER_CERTIFICATE_PATH')
        # Path to the key of the gRPC server required for the secure mode
        if os.getenv('GRPC_SERVER_KEY_PATH') is not None:
            self.grpc_server_key_path = os.getenv('GRPC_SERVER_KEY_PATH')
        # Define whether to enable the debug mode or not
        if os.getenv('DEBUG') is not None:
            self.debug = os.getenv('DEBUG')
            # Values provided in .env files are returned as strings
            # We need to convert them to bool
            if self.debug.lower() == 'true':
                self.debug = True
            elif self.debug.lower() == 'false':
                self.debug = False
            else:
    # Invalid value for this parameter
                self.debug = None
    def validate_config(self):
        """Check if the configuration is valid"""

        logger.info('*** Validating configuration')
        success = True
        # Validate gRPC IP address
        if not validate_ip_address(self.grpc_ip):
            logger.critical(
                'GRPC_IP is an invalid IP address: %s', self.grpc_ip)
            success = False
        # Validate gRPC port
        if self.grpc_port <= 0 or self.grpc_port >= 65536:
            logger.critical('GRPC_PORT out of range: %s', self.grpc_port)
            success = False
        # Validate gRPC secure mode parameters
        if self.grpc_secure:
            # Validate GRPC_SERVER_CERTIFICATE_PATH
            if self.grpc_server_certificate_path is None:
                logger.critical('Set GRPC_SERVER_CERTIFICATE_PATH variable '
                                'in configuration file (.env file)')
                success = False
            if not os.path.exists(self.grpc_server_certificate_path):
                logger.critical(
                    'GRPC_SERVER_CERTIFICATE_PATH variable to a non '
                    'existing folder: %s', self.grpc_server_certificate_path)
                success = False
            # Validate GRPC_SERVER_KEY_PATH
            if self.grpc_server_key_path is None:
                logger.critical('Set GRPC_SERVER_KEY_PATH variable in '
                                'configuration file (.env file)')
                success = False
            if not os.path.exists(self.grpc_server_key_path):
                logger.critical(
                    'GRPC_SERVER_KEY_PATH variable in .env points to a '
                    'non existing folder: %s', self.grpc_server_key_path)
                success = False
        # Return result
        return success
        
    def print_config(self):
        """Pretty print the current configuration"""

        print()
        print('****************** CONFIGURATION ******************')
        print()
        #print('Enable SRv6 Manager support: %s' % self.enable_srv6_manager)
        print('IP address of the gRPC server: %s' % self.grpc_ip)
        print('Port of the gRPC server: %s' % self.grpc_port)
        print('Enable secure mode for gRPC server: %s' % self.grpc_secure)
        if self.grpc_secure:
            print('Path of the certificate for the gRPC server: %s'
                  % self.grpc_server_certificate_path)
            print('Path of the private key for the gRPC server: %s'
                  % self.grpc_server_key_path)
        print('Enable debug: %s' % self.debug)
        print('Enable SRv6 PM Manager support: %s'
              % self.enable_srv6_pm_manager)
        if self.enable_srv6_pm_manager:
            print('Path of the srv6-pm-xdp-ebpf repository: %s'
                  % self.srv6_pm_xdp_ebpf_path)
            print('Path of the rose-srv6-data-plane repository: %s'
                  % self.rose_srv6_data_plane_path)
        print()
        print('***************************************************')
        print()
        print()

# Check whether we have root permission or not
# Return True if we have root permission, False otherwise
def check_root():
    """Return True if this program has been executed as root,
    False otherwise"""

    return os.getuid() == 0


if __name__ == "__main__":
    """Entry point for dataplane-manager"""
    # Parse command-line arguments
    args = parse_arguments()
    # Path to the .env file containing the parameters for the dataplane manager'
    env_file = args.env_file
    # Create a new configuration object
    config = Config()
    # Load configuration from .env file
    if env_file is not None and os.path.exists(env_file):
        config.load_config(env_file)
    else:
        logger.warning('Configuration file not found. '
                       'Using default configuration.')
    if args.debug:
        logger.setLevel(level=logging.DEBUG)
        config.debug = args.debug
    else:
        logger.setLevel(level=logging.INFO)
    server_debug = logger.getEffectiveLevel() == logging.DEBUG
    logging.basicConfig(level=logging.DEBUG,
            format="%(asctime)s| %(levelname).8s | %(name)-10s | %(message)s")
    logging.info('SERVER_DEBUG: %s', server_debug)
    # Validate configuration
    if not config.validate_config():
        logger.critical('Invalid configuration\n')
        sys.exit(-2)
    # Print configuration
    config.print_config()
    grpc_ip =  config.grpc_ip
    grpc_port = config.grpc_port 
    secure = config.grpc_secure
    certificate = config.grpc_server_certificate_path
    key = config.grpc_server_key_path
    start_server(grpc_ip, grpc_port, secure, certificate, key)
    
    
