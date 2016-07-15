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
#   - Some code adopted from Lawrence Lui's <lawrence.lui@dimensiondata.com>
#     didata_cli contributions.
#
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.loadbalancer.types import Provider as LBProvider
    from libcloud.compute.types import Provider as ComputeProvider
    from libcloud.loadbalancer.providers import get_driver as get_lb_driver
    from libcloud.compute.providers import get_driver as get_compute_driver
    from libcloud.loadbalancer.base import Member
    from libcloud.common.dimensiondata import DimensionDataPublicIpBlock
    from libcloud.loadbalancer.base import Algorithm, Driver, LoadBalancer
    import libcloud.security
    from ansible.module_utils.dimensiondata import *
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False
import sys


dd_regions = get_dd_regions()
credentials = get_credentials()

network_domain_name = "ansible-capabilities-demo"
verify_ssl_cert = False
region = 'dd-na'
location = 'NA12'

def get_network_by_name(driver, name, location):
    networks = driver.ex_list_network_domains(location=location)
    network = filter(lambda x: x.name == name, networks)
    if isinstance(network, list):
        return network[0]
    else:
        return network


def get_node_by_name(driver, location, name):
    node = driver.list_nodes(location, name)
    return node


def main():
    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud is required for this module.')

    user_id = credentials['user_id']
    key = credentials['key']

    # Instantiate drivers
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    # instatiate LB Driver
    DimensionDataLB = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_driver = DimensionDataLB(user_id, key, region=region)
    # instatiate Compute Driver
    DimensionDataCompute = get_compute_driver(ComputeProvider.DIMENSIONDATA)
    compute_driver = DimensionDataCompute(user_id, key, region=region)


    domain = get_network_by_name(compute_driver, network_domain_name, location)
    lb_driver.ex_set_current_network_domain(domain.id)
    # print domain
    # node = compute_driver.list_nodes(location, 'test1')[0]
    # print node
    # members = lb_driver.ex_create_node(domain.id, node.name, '192.168.0.10', "my node")
    # member = Member(node.id, node.private_ips[0], 80)
    # print members
    # network = get_network_by_name(compute_driver, network_domain, location)
    # print network
    # res = lb_driver.list_balancers()
#    for lb in res:
#        print lb.__dict__
#    sys.exit()
    # print lb_driver.create_balancer("test_LB", 80, 'http', Algorithm.ROUND_ROBIN, [member])
    # print lb_driver.list_balancers()
    try:
        res = lb_driver.ex_get_pools()
        print res[0].__dict__
        # nat_rules = compute_driver.ex_list_nat_rules(domain)
        # print nat_rules
        # print nat_rules[0].__dict__
        # rule = filter(lambda x: x.external_ip == '168.128.28.211' and x.internal_ip == '10.0.0.10', nat_rules)
        # print rule[0].__dict__
        # res = compute_driver.ex_get_nat_rule(domain, nat_rules[0].id)
        # print res.__dict__
        # res = compute_driver.ex_create_nat_rule(domain, '10.1.1.8', '168.128.28.125')
        # print res
        # res = compute_driver.ex_delete_nat_rule(res)
        # print res
        # res = compute_driver.ex_list_nat_rules(domain)
        # print res
        # res = compute_driver.ex_get_nat_rule(domain, res[0].id)
        # print res.__dict__
        # res = compute_driver.ex_list_public_ip_blocks(domain)
        # print res
        # res = compute_driver.ex_get_public_ip_block(res[0].id)
        # print res.__dict__
        # res = compute_driver.list_nodes(ex_location='NA12', ex_network_domain='3e79e64a-7a89-4363-93b0-4d18eac9338e')
        # print res[0].__dict__
        # res = compute_driver.ex_get_node_by_id('5c4c08a2-d1e1-4211-866a-4209ccfcd1f7')
        # print res.__dict__
        # client = compute_driver
        # domain = client.ex_get_network_domain('2a35dd88-7769-42df-999a-82dfbfdb5d1b')
        # print domain.__dict__


        # image_match_name = 'CentOS 7 64-bit 2 CPU'
        # images = client.list_images(domain.location.id)
        # matched_images = list(filter(lambda x: x.name == image_match_name,
        #                       images))
        # print matched_images

        # vlans = client.ex_list_vlans(domain.location.id, domain.id, 'ansible-demo')
        # vlans2 = client.ex_list_vlans(domain.location.id, domain.id, 'ansible-demo2')


        # node = client.create_node("test1", matched_images[0].id, 'password123',
        #                           'description',
        #                           ex_network_domain='2a35dd88-7769-42df-999a-82dfbfdb5d1b',
        #                           ex_vlan=vlans[0].id,
        #                           ex_primary_ipv4=None,
        #                           ex_memory_gb=2,
        #                           ex_primary_dns='4.2.2.2',
        #                           ex_secondary_dns='8.8.8.8',
        #                           ex_additional_nics_vlan=[vlans2[0].id],
        #                           ex_additional_nics_ipv4=None)
    except DimensionDataAPIException as e:
        print e.code

main()
