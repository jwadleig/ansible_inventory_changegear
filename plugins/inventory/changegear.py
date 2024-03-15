# -*- coding: utf-8 -*-
# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: online
    author:
      - John Wadleigh (@ansiblejunky)
    short_description: ChangeGear inventory plugin for Ansible Automation Platform
    description:
        - Get inventory hosts from ChangeGear API
    options:
        plugin:
            description: Ensures this is a source file for the 'changegear' plugin.
            required: true
            choices: ['changegear']
        hostname:
            required: true
            description: Hostname for API endpoint
        apikey:
            required: true
            description: API Key for basic authentication
            env:
                - name: CHANGEGEAR_APIKEY
        username:
            description: Username for basic authentication
            type: string
            required: true
            env:
                - name: CHANGEGEAR_USERNAME
        password:
            descrption: Password for basic authentication
            type: string
            required: true
            env:
                - name: CHANGEGEAR_PASSWORD
        location:
            description: Location filter for stations
            type: string
            required: true
        department:
            description: Department filter for stations
            type: string
            required: true
        timeout:
            description: Set timeout for all requests (default 10)
            type: integer
'''

EXAMPLES = r'''
# Example command line: ansible-inventory --list -i changegear.yml

# changegear.yml file in YAML format
plugin: changegear
location: Austin
department: ABC
username: user
password: pass
hostname: station-api-dev.example.com
timeout: 120
apikey: mysamplekey

# Example ansible.cfg to enable the plugin
[defaults]
inventory_plugins=plugins/inventory/

[inventory]
enable_plugins=changegear
'''

import json
from sys import version as python_version

from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.ansible_release import __version__ as ansible_version
from ansible.module_utils.six.moves.urllib.parse import urljoin
from urllib.parse import quote as urlquote, urlparse, urljoin, urlencode

class InventoryModule(BaseInventoryPlugin):
    NAME = 'changegear'

    def extract_public_ipv4(self, host_infos):
        try:
            return host_infos["network"]["ip"][0]
        except (KeyError, TypeError, IndexError):
            self.display.warning("An error happened while extracting public IPv4 address. Information skipped.")
            return None

    def extract_private_ipv4(self, host_infos):
        try:
            return host_infos["network"]["private"][0]
        except (KeyError, TypeError, IndexError):
            self.display.warning("An error happened while extracting private IPv4 address. Information skipped.")
            return None

    def extract_os_name(self, host_infos):
        try:
            return host_infos["os"]["name"]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting OS name. Information skipped.")
            return None

    def extract_os_version(self, host_infos):
        try:
            return host_infos["os"]["version"]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting OS version. Information skipped.")
            return None

    def extract_hostname(self, host_infos):
        try:
            return host_infos["hostname"]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting hostname. Information skipped.")
            return None

    def extract_location(self, host_infos):
        try:
            return host_infos["location"]["datacenter"]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting datacenter location. Information skipped.")
            return None

    def extract_offer(self, host_infos):
        try:
            return host_infos["offer"]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting commercial offer. Information skipped.")
            return None

    def extract_rpn(self, host_infos):
        try:
            return self.rpn_lookup_cache[host_infos["id"]]
        except (KeyError, TypeError):
            self.display.warning("An error happened while extracting RPN information. Information skipped.")
            return None

    def _fetch(self, url):
        try:
            response = open_url(url, headers=self.headers, method='GET', timeout=self.timeout, url_username=self.username, url_password=self.password, force_basic_auth=True)
        except Exception as e:
            self.display.warning("An error happened while fetching: %s" % url)
            self.display.error("Error: %s" % str(e))
            return None

        try:
            raw_data = to_text(response.read(), errors='surrogate_or_strict')
        except UnicodeError:
            raise AnsibleError("Incorrect encoding of fetched payload from Online servers")

        try:
            return json.loads(raw_data)
        except ValueError:
            raise AnsibleError("Incorrect JSON payload")

    @staticmethod
    def extract_rpn_lookup_cache(rpn_list):
        lookup = {}
        for rpn in rpn_list:
            for member in rpn["members"]:
                lookup[member["id"]] = rpn["name"]
        return lookup

    def _fill_host_variables(self, hostname, host_infos):
        targeted_attributes = (
            "offer",
            "id",
            "hostname",
            "location",
            "boot_mode",
            "power",
            "last_reboot",
            "anti_ddos",
            "hardware_watch",
            "support"
        )
        for attribute in targeted_attributes:
            self.inventory.set_variable(hostname, attribute, host_infos[attribute])

        if self.extract_public_ipv4(host_infos=host_infos):
            self.inventory.set_variable(hostname, "public_ipv4", self.extract_public_ipv4(host_infos=host_infos))
            self.inventory.set_variable(hostname, "ansible_host", self.extract_public_ipv4(host_infos=host_infos))

        if self.extract_private_ipv4(host_infos=host_infos):
            self.inventory.set_variable(hostname, "public_ipv4", self.extract_private_ipv4(host_infos=host_infos))

        if self.extract_os_name(host_infos=host_infos):
            self.inventory.set_variable(hostname, "os_name", self.extract_os_name(host_infos=host_infos))

        if self.extract_os_version(host_infos=host_infos):
            self.inventory.set_variable(hostname, "os_version", self.extract_os_name(host_infos=host_infos))

    def _filter_host(self, host_infos, hostname_preferences):

        for pref in hostname_preferences:
            if self.extractors[pref](host_infos):
                return self.extractors[pref](host_infos)

        return None

    def do_server_inventory(self, host_infos, hostname_preferences, group_preferences):

        hostname = self._filter_host(host_infos=host_infos,
                                     hostname_preferences=hostname_preferences)

        # No suitable hostname were found in the attributes and the host won't be in the inventory
        if not hostname:
            return

        self.inventory.add_host(host=hostname)
        self._fill_host_variables(hostname=hostname, host_infos=host_infos)

        for g in group_preferences:
            group = self.group_extractors[g](host_infos)

            if not group:
                return

            self.inventory.add_group(group=group)
            self.inventory.add_host(group=group, host=hostname)

    # Required function for Ansible inventory plugins
    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('changegear.yaml', 'changegear.yml')):
                valid = True
        return valid

    # Required function for Ansible inventory plugins
    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)

        # Load configuration options from inventory plugin
        self._read_config_data(path=path)
        self.apikey = self.get_option("apikey")
        self.location = self.get_option("location")
        self.department = self.get_option("department")
        self.timeout = int(self.get_option("timeout"))
        self.username = r"{}".format(self.get_option("username"))
        self.password = r"{}".format(self.get_option("password"))
        self.hostname = self.get_option("hostname")
        self.endpoint = "https://" + self.hostname + "/"

        self.extractors = {
            "public_ipv4": self.extract_public_ipv4,
            "private_ipv4": self.extract_private_ipv4,
            "hostname": self.extract_hostname,
        }

        self.group_extractors = {
            "location": self.extract_location,
            "offer": self.extract_offer,
            "rpn": self.extract_rpn
        }

        self.headers = {
            'API-KEY': self.apikey,
            'User-Agent': "ansible %s Python %s" % (ansible_version, python_version.split(' ', 1)[0]),
            'Accept': 'application/json',
            'Content-type': 'application/json'
        }

        api = "/station-api/station/v3/"
        # TODO: Use urlencode to encode the strings
        search = "search?query=%22department%3D%27" + self.department + "%27%20and%20site%3D%27" + self.location + "%27%20and%20status%3D%27Reserved%27%22&page=1&pagesize=50"        
        url = urljoin(self.endpoint, api) + search
        response = self._fetch(url=url)

        self.inventory.add_group(group=self.location)
        for item in response:
            station = item.get('station')
            hardware = station.get('Hardware')
            system = hardware.get('System')
            hostname = system.get('Hostname')
            ip_addr = system.get('IP')
            if hostname:
                self.inventory.add_host(group=self.location, host=hostname)
            elif ip_addr:
                self.inventory.add_host(group=self.location, host=ip_addr)

        # self.do_server_inventory(host_infos=raw_server_info, hostname_preferences=hostname_preferences, group_preferences=group_preferences)