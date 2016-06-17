#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Dimension Data
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   - Aimon Bustardo <aimon.bustardo@dimensiondata.com>
#
# Common methods to be used by versious module components
import os
import ConfigParser
from os.path import expanduser
from libcloud.common.dimensiondata import API_ENDPOINTS
from uuid import UUID


# -------------------------
# This method will get user_id and key from environemnt or dot file.
# Environment takes priority.
#
# To set in environment:
# export DIDATA_USER='myusername'
# export DIDATA_PASSWORD='mypassword'
#
# To set in dot file place a file at ~/.dimensiondata with
# the following contents:
# [dimensiondatacloud]
# DIDATA_USER: myusername
# DIDATA_PASSWORD: mypassword
# -------------------------
def get_credentials():
    user_id = None
    key = None

    # Attempt to grab from environment
    if 'DIDATA_USER' in os.environ and 'DIDATA_PASSWORD' in os.environ:
        user_id = os.environ['DIDATA_USER']
        key = os.environ['DIDATA_PASSWORD']

    # Environment failed try dot file
    if user_id is None or key is None:
        home = expanduser('~')
        config = ConfigParser.RawConfigParser()
        config.read("%s/.dimensiondata" % home)
        try:
            user_id = config.get("dimensiondatacloud", "DIDATA_USER")
            key = config.get("dimensiondatacloud", "DIDATA_PASSWORD")
        except:
            pass

    # Return False if either are not found
    if user_id is None or key is None:
        return False

    # Both found, return data
    return dict(user_id=user_id, key=key)


# -------------------------
# Get the list of available regions
# whos vendor is Dimension Data.
# -------------------------
def get_dd_regions():
    # Get endpoints
    all_regions = API_ENDPOINTS.keys()

    # filter to only DimensionData endpoints
    region_list = filter(lambda i: i.startswith('dd-'), all_regions)

    # Strip prefix
    regions = [region[3:] for region in region_list]

    return regions


# ----------------------------------------
# Get a network domain object by its name
# ----------------------------------------
def get_network_domain_by_name(driver, name, location):
    networks = driver.ex_list_network_domains(location=location)
    network = filter(lambda x: x.name == name, networks)
    if len(network) > 0:
        return network[0]
    else:
        return None


# ---------------------------------------------
# Get a network domain object by its name or id
# ---------------------------------------------
def get_network_domain(driver, locator, location):
    if is_uuid(locator):
        net_id = locator
    else:
        networks = driver.ex_list_network_domains(location=location)
        found_networks = filter(lambda x: x.name == locator, networks)
        if len(found_networks) > 0:
            net_id = found_networks[0].id
        else:
            return False
    try:
        return driver.ex_get_network_domain(net_id)
    except:
        return False


# ---------------------------------------------
# Get a VLAN object by its name or id
# ---------------------------------------------
def get_vlan(driver, locator, location, network_domain):
    if is_uuid(locator):
        vlan_id = locator
    else:
        vlans = driver.ex_list_vlans(location=location,
                                     network_domain=network_domain)
        found_vlans = filter(lambda x: x.name == locator, vlans)
        if len(found_vlans) > 0:
            vlan_id = found_vlans[0].id
        else:
            return False
    try:
        return driver.ex_get_vlan(vlan_id)
    except:
        return False


# ----------------------------------------
# Get a locations MCP version
# ----------------------------------------
def get_mcp_version(driver, location):
    # Get location to determine if MCP 1.0 or 2.0
    location = driver.ex_get_location_by_id(location)
    if 'MCP 2.0' in location.name:
        return '2.0'
    return '1.0'


# ---------------------
# Test if valid v4 UUID
# ---------------------
def is_uuid(u, version=4):
    try:
        uuid_obj = UUID(u, version=version)
        return str(uuid_obj) == u
    except:
        return False
