#!/usr/bin/python
# -*- coding: utf-8 -*-
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
    # lb_driver.ex_set_current_network_domain(domain.id)
    lb_driver.ex_set_current_network_domain('1596be10-d690-413d-8f76-65498809f76f')
    try:
        res = lb_driver.ex_get_pools()
        pool = filter(lambda x: x.name == 'test', res)
        print pool[0].__dict__
        hms = lb_driver.ex_get_default_health_monitors(domain.id)
        print hms
    except DimensionDataAPIException as e:
        print e.code

main()
