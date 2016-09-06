#!/usr/bin/python

''' DimensionData network object purger

'''
__author__ = 'Jay Riddell'

try:
    import argparse
    import sys
    from ansible.module_utils.basic import *
    from ansible.module_utils.dimensiondata import *
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.loadbalancer.types import Provider as LBProvider
    from libcloud.compute.types import Provider as ComputeProvider
    from libcloud.loadbalancer.providers import get_driver as get_lb_driver
    from libcloud.compute.providers import get_driver as get_cp_driver
    HAS_LIBRARIES = True
except:
    HAS_LIBRARIES = False

global network
global region
global location
global quiet
global showparams
global listonly
global lbs
global lbnodes
global pools
global cpnodes
global vlans
global nats
global ips
global firewalls


def kill_members_in_pool(lb_driver, pool_id, quiet, listonly):
    try:
        show(quiet, '     - - - - - - Members/Nodes in Pool - - - - -')
        members = lb_driver.ex_get_pool_members(pool_id)

        for m in members:
            show(quiet, "        Found member = %s" % m.name)

            if not listonly:
                res = lb_driver.ex_destroy_pool_member(m, destroy_node=True)

                show(quiet, "        Result from clearing "
                     "member/node %s ==> %s" % (m.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of pool members: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_pools(lb_driver, network_domain_id, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Pools - - - - -')

        pools = lb_driver.ex_get_pools(
            ex_network_domain_id=network_domain_id)

        for p in pools:
            show(quiet, "    Found pool = %s" % p.name)

            if not listonly:
                # first, kill any members/nodes assoc with the pool
                kill_members_in_pool(lb_driver, p.id, quiet, listonly)

                # now kill the pool itself
                res = lb_driver.ex_destroy_pool(p)

                show(quiet, "    Result from clearing pool %s ==> %s" %
                     (p.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of pools: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_lb_nodes(lb_driver, network_domain_id, quiet, listonly):
    try:
        show(quiet, ' - - - - - - LB Nodes - - - - -')

        nodes = lb_driver.ex_get_nodes(
            ex_network_domain_id=network_domain_id)

        for n in nodes:
            show(quiet, "    Found LB node = %s" % n.name)

            if not listonly:
                res = lb_driver.ex_destroy_node(n.id)

                show(quiet, "    Result from clearing LB node %s ==> %s" %
                     (n.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of LB nodes: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_load_balancers(lb_driver, network_domain_id, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Load Balancers - - - - -')

        virt_lists = lb_driver.list_balancers(
            ex_network_domain_id=network_domain_id)

        for v in virt_lists:
            show(quiet, "    Found loadbalacer = %s" % v.name)

            if not listonly:
                res = lb_driver.destroy_balancer(v)

                show(quiet, "    Result from clearing "
                     "loadbalancer %s ==> %s" % (v.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of load balancers: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_cpnodes(cp_driver, network_domain, quiet, listonly):
    try:
        show(quiet, ' - - - - - - CpNodes - - - - -')

        servers = cp_driver.list_nodes(ex_network_domain=network_domain)

        for s in servers:
            show(quiet, "    Found cpnode = %s" % s.name)

            if not listonly:
                res = cp_driver.destroy_node(s)

                show(quiet, "    Result from clearing cpnode %s ==> %s" %
                     (s.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of cpnodes: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_vlans(cp_driver, network_domain, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Vlans - - - - -')

        vlans = cp_driver.ex_list_vlans(network_domain=network_domain)

        for v in vlans:
            show(quiet, "    Found vlan = %s" % v.name)

            if not listonly:
                res = cp_driver.ex_delete_vlan(v)

                show(quiet, "    Result from clearing vlan %s ==> %s" %
                     (v.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of vlans: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_nats(cp_driver, network_domain, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Nat Rules - - - - -')

        nat_rules = cp_driver.ex_list_nat_rules(network_domain=network_domain)

        for n in nat_rules:
            show(quiet, "    Found Nat Rule = %s" % n.name)

            if not listonly:
                res = cp_driver.ex_delete_nat_rule(n)

                show(quiet, "    Result from clearing Nat Rule %s ==> %s" %
                     (n.name, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of nat rules: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_ips(cp_driver, network_domain, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Public IP Blocks - - - - -')

        ip_blocks = cp_driver.ex_list_public_ip_blocks(
            network_domain=network_domain)

        for ips in ip_blocks:
            show(quiet, "    Found IP Block = %s" % ips.base_ip)

            if not listonly:
                res = cp_driver.ex_delete_public_ip_block(ips)

                show(quiet, "    Result from clearing Public "
                     "IP Block %s ==> %s" % (ips.base_ip, res))

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of public ip blocks: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def kill_firewalls(cp_driver, network_domain, quiet, listonly):
    try:
        show(quiet, ' - - - - - - Firewall Rules - - - - -')

        rules = cp_driver.ex_list_firewall_rules(
            network_domain=network_domain, page_size=1000)

        if rules is not None and not listonly:
            show(quiet, "    Note: Cannot delete DEFAULT firewall rules!")

        for r in rules:
            if not listonly:
                # check if this is a DEFAULT firewall rule
                #
                # key off the name
                if 'DEFAULT' not in r.name:
                    show(quiet, "    Found Firewall Rule = %s" % r.name)
                    res = cp_driver.ex_delete_firewall_rule(r)

                    show(quiet, "    Result from clearing Firewall "
                         "Rule %s ==> %s" % (r.name, res))
                else:
                    show(quiet, "    Not deleting %s" % r.name)

    except DimensionDataAPIException as e:
        sys.exit("Failed to retrieve a list of firewall rules: %s" % e)
    # except:
    #     sys.exit("Unknown exception: %s" % sys.exc_info()[0])


def get_args():
    global network, region
    global location
    global quiet
    global showparams
    global listonly
    global lbs
    global lbnodes
    global pools
    global cpnodes
    global vlans
    global nats
    global ips
    global firewalls

    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Util to clear/remove objects from a' +
        ' specified DimensionData network.')
    # Add arguments
    parser.add_argument(
        '--region', type=str, help='Region', required=True)
    parser.add_argument(
        '--network', type=str, help='Network name', required=True)
    parser.add_argument(
        '--location', type=str, help='Network location', required=True)
    parser.add_argument(
        '--all', help='clear ALL', required=False,
        action='store_true')
    parser.add_argument(
        '--lbs', help='clear virt-lists/load-balancers',
        required=False, action='store_true')
    parser.add_argument(
        '--lbnodes', help='clear LoadBalancer nodes', required=False,
        action='store_true')
    parser.add_argument(
        '--pools', help='clear pools', required=False,
        action='store_true')
    parser.add_argument(
        '--cpnodes', help='clear compute nodes aka servers',
        required=False, action='store_true')
    parser.add_argument(
        '--vlans', help='clear vlans', required=False,
        action='store_true')
    parser.add_argument(
        '--nats', help='clear compute Nat Rules',
        required=False, action='store_true')
    parser.add_argument(
        '--ips', help='clear compute Public IP Blocks',
        required=False, action='store_true')
    parser.add_argument(
        '--firewalls', help='clear firewall rules',
        required=False, action='store_true')
    parser.add_argument(
        '--quiet', help='quiet aka no normal output', required=False,
        default=False, action='store_true')
    parser.add_argument(
        '--showparams', help='show passed params', required=False,
        default=False, action='store_true')
    parser.add_argument(
        '--listonly', help='only list aka do not clear anything '
        'aka READ-ONLY', required=False, default=False, action='store_true')

    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    network = args.network
    region = 'dd-%s' % args.region
    location = args.location
    quiet = args.quiet
    showparams = args.showparams
    listonly = args.listonly
    lbs = args.lbs or args.all
    lbnodes = args.lbnodes or args.all
    pools = args.pools or args.all
    cpnodes = args.cpnodes or args.all
    vlans = args.vlans or args.all
    nats = args.nats or args.all
    ips = args.ips or args.all
    firewalls = args.firewalls or args.all

    # Return all variable values
    # return network, region, location, lbs, lbnodes, pools, quiet,
    # cpnodes, vlans, nats, showparams, ips, firewalls
    return


def show(quiet_flag, txt):
    if not quiet_flag:
        print txt


def main():
    global network
    global region
    global location
    global quiet
    global showparams
    global listonly
    global lbs
    global lbnodes
    global pools
    global cpnodes
    global vlans
    global nats
    global ips
    global firewalls

    # ensure all the libraries loaded
    if not HAS_LIBRARIES:
        sys.exit("Not all libraries loaded")

    # Match return values from get_arguments()
    # and assign to their respective variables
    # network, region, location, lbs,
    # nodes, ips, pools, quiet = get_args()
    get_args()

    # Print the values
    if showparams:
        print("\nPassed params:")
        print("------------------------------------------")
        print("network:              [ %s ]" % network)
        print("region:               [ %s ]" % region)
        print("location:             [ %s ]" % location)
        print("lbs:                  [ %s ]" % lbs)
        print("lbnodes:              [ %s ]" % lbnodes)
        print("pools:                [ %s ]" % pools)
        print("cpnodes:              [ %s ]" % cpnodes)
        print("vlans:                [ %s ]" % vlans)
        print("nats:                 [ %s ]" % nats)
        print("ips:                  [ %s ]" % ips)
        print("firewalls:            [ %s ]" % firewalls)
        print("quiet:                [ %s ]" % quiet)
        print("listonly:             [ %s ]" % listonly)
        print("------------------------------------------")
        print(" ")

    # set short vars for readability
    credentials = get_credentials()
    if credentials is False:
        sys.exit("User credentials not found")

    user_id = credentials['user_id']
    key = credentials['key']

    # -------------------
    # Instantiate drivers
    # -------------------

    # libcloud.security.VERIFY_SSL_CERT = True

    # Instantiate Load Balancer Driver
    DDLoadBalancer = get_lb_driver(LBProvider.DIMENSIONDATA)
    lb_driver = DDLoadBalancer(user_id, key, region=region)

    # Instantiate Compute Driver
    DDCompute = get_cp_driver(ComputeProvider.DIMENSIONDATA)
    cp_driver = DDCompute(user_id, key, region=region)

    # Get Network Domain Object
    net_domain = get_network_domain(cp_driver, network, location)
    if net_domain is False:
        sys.exit("Network could not be found.")

    # Set network domain
    try:
        lb_driver.ex_set_current_network_domain(net_domain.id)
    except:
        sys.exit("Current network domain could not be set.")

    # ok, let's nuke some objects !!
    if lbs:
        kill_load_balancers(lb_driver, net_domain.id, quiet, listonly)

    if pools:
        kill_pools(lb_driver, net_domain.id, quiet, listonly)

    if lbnodes:
        kill_lb_nodes(lb_driver, net_domain.id, quiet, listonly)

    if vlans:
        kill_vlans(cp_driver, net_domain, quiet, listonly)

    if cpnodes:
        kill_cpnodes(cp_driver, net_domain, quiet, listonly)

    if nats:
        kill_nats(cp_driver, net_domain, quiet, listonly)

    if ips:
        kill_ips(cp_driver, net_domain, quiet, listonly)

    if firewalls:
        kill_firewalls(cp_driver, net_domain, quiet, listonly)

    show(quiet, " ")
    show(quiet, 'End.')

if __name__ == '__main__':
    main()
