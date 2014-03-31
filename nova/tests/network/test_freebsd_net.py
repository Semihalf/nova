# Copyright 2014 Semihalf
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" Tests for freebsd_net networking driver.

Some tests implementation has been borrowed from test_linux_net.py copyrighted
by NTT.
"""

import datetime
import os

import mock
import mox
from oslo.config import cfg

from nova import context
from nova import db
from nova import exception
from nova.network import driver
from nova.network import freebsd_net
from nova.objects import fixed_ip as fixed_ip_obj
from nova.openstack.common import fileutils
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import processutils
from nova.openstack.common import timeutils
from nova import test
from nova import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

HOST = "testhost"


class FreeBSDNetworkTestCase(test.NoDBTestCase):

    def setUp(self):
        super(FreeBSDNetworkTestCase, self).setUp()
        self.driver = driver.load_network_driver('nova.network.freebsd_net')
        self.driver.db = db
        self.context = context.RequestContext('testuser', 'testproject',
                                              is_admin=True)

    def test_flat_override(self):
        """Makes sure flat_interface flag overrides network bridge_interface.

        Allows heterogeneous networks a la bug 833426
        """

        driver = freebsd_net.FreeBSDBridgeInterfaceDriver()

        info = {}

        @staticmethod
        def test_ensure(bridge, interface, network, gateway):
            info['passed_interface'] = interface

        self.stubs.Set(freebsd_net.FreeBSDBridgeInterfaceDriver,
                       'ensure_bridge', test_ensure)

        network = {
                "bridge": "br100",
                "bridge_interface": "base_interface",
        }
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "base_interface")
        self.flags(flat_interface="override_interface")
        driver.plug(network, "fakemac")
        self.assertEqual(info['passed_interface'], "override_interface")

    def _test_dnsmasq_execute(self, extra_expected=None):
        network_ref = {'id': 'fake',
                       'label': 'fake',
                       'multi_host': False,
                       'cidr': '10.0.0.0/24',
                       'netmask': '255.255.255.0',
                       'dns1': '8.8.4.4',
                       'dhcp_start': '1.0.0.2',
                       'dhcp_server': '10.0.0.1'}

        def fake_execute(*args, **kwargs):
            executes.append(args)
            return "", ""

        def fake_add_dhcp_mangle_rule(*args, **kwargs):
            executes.append(args)

        self.stubs.Set(freebsd_net, '_execute', fake_execute)

        self.stubs.Set(os, 'chmod', lambda *a, **kw: None)
        self.stubs.Set(freebsd_net, 'write_to_file', lambda *a, **kw: None)
        self.stubs.Set(freebsd_net, '_dnsmasq_pid_for', lambda *a, **kw: None)
        dev = 'br100'

        default_domain = CONF.dhcp_domain
        for domain in ('', default_domain):
            executes = []
            CONF.dhcp_domain = domain
            freebsd_net.restart_dhcp(self.context, dev, network_ref)
            expected = ['env',
            'CONFIG_FILE=%s' % jsonutils.dumps(CONF.dhcpbridge_flagfile),
            'NETWORK_ID=fake',
            'dnsmasq',
            '--strict-order',
            '--bind-interfaces',
            '--conf-file=%s' % CONF.dnsmasq_config_file,
            '--pid-file=%s' % freebsd_net._dhcp_file(dev, 'pid'),
            '--listen-address=%s' % network_ref['dhcp_server'],
            '--except-interface=lo',
            "--dhcp-range=set:%s,%s,static,%s,%ss" % (network_ref['label'],
                                                    network_ref['dhcp_start'],
                                                    network_ref['netmask'],
                                                    CONF.dhcp_lease_time),
            '--dhcp-lease-max=256',
            '--dhcp-hostsfile=%s' % freebsd_net._dhcp_file(dev, 'conf'),
            '--dhcp-script=%s' % CONF.dhcpbridge,
            '--leasefile-ro']

            if CONF.dhcp_domain:
                expected.append('--domain=%s' % CONF.dhcp_domain)

            if extra_expected:
                expected += extra_expected
            self.assertEqual([tuple(expected)], executes)

    def test_dnsmasq_execute(self):
        self._test_dnsmasq_execute()

    def test_dnsmasq_execute_dns_servers(self):
        self.flags(dns_server=['1.1.1.1', '2.2.2.2'])
        expected = [
            '--no-hosts',
            '--no-resolv',
            '--server=1.1.1.1',
            '--server=2.2.2.2',
        ]
        self._test_dnsmasq_execute(expected)

    def test_dnsmasq_execute_use_network_dns_servers(self):
        self.flags(use_network_dns_servers=True)
        expected = [
            '--no-hosts',
            '--no-resolv',
            '--server=8.8.4.4',
        ]
        self._test_dnsmasq_execute(expected)

    def test_ensure_bridge(self):
        self.mox.StubOutWithMock(self.driver, '_device_exists')
        self.mox.StubOutWithMock(self.driver, '_execute')
        self.mox.StubOutWithMock(self.driver, '_device_is_bridge_member')
        self.mox.StubOutWithMock(self.driver, '_route_list')
        self.mox.StubOutWithMock(self.driver, '_delete_routes_from_list')
        self.mox.StubOutWithMock(self.driver, '_add_routes_from_list')
        self.mox.StubOutWithMock(self.driver, '_ip_list')
        self.mox.StubOutWithMock(self.driver, '_delete_ip_from_list')
        self.mox.StubOutWithMock(self.driver, '_add_ip_from_list')

        self.driver._device_exists('bridge0').AndReturn(True)
        self.driver._device_is_bridge_member('bridge0', 'em0').AndReturn(False)
        self.driver._execute('ifconfig', 'bridge0', 'addm', 'em0',
                             check_exit_code=0, run_as_root=True)
        self.driver._execute('ifconfig', 'em0', 'up', check_exit_code=0,
                             run_as_root=True)
        self.driver._route_list('em0')
        self.driver._delete_routes_from_list(mox.IgnoreArg())
        self.driver._ip_list(mox.IgnoreArg())
        self.driver._delete_ip_from_list(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver._add_ip_from_list(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver._add_routes_from_list(mox.IgnoreArg())

        self.mox.ReplayAll()
        self.driver.FreeBSDBridgeInterfaceDriver.ensure_bridge('bridge0', 'em0')

    def test_ensure_bridge_no_bridge_exists(self):
        self.mox.StubOutWithMock(self.driver, '_device_exists')
        self.mox.StubOutWithMock(self.driver, '_execute')
        self.mox.StubOutWithMock(self.driver, '_device_is_bridge_member')
        self.mox.StubOutWithMock(self.driver, '_route_list')
        self.mox.StubOutWithMock(self.driver, '_delete_routes_from_list')
        self.mox.StubOutWithMock(self.driver, '_add_routes_from_list')
        self.mox.StubOutWithMock(self.driver, '_ip_list')
        self.mox.StubOutWithMock(self.driver, '_delete_ip_from_list')
        self.mox.StubOutWithMock(self.driver, '_add_ip_from_list')

        self.driver._device_exists('bridge0').AndReturn(False)
        self.driver._execute('ifconfig', 'bridge0', 'create',
                     check_exit_code=0, run_as_root=True)
        self.driver._execute('ifconfig', 'bridge0', 'up', check_exit_code=0,
                             run_as_root=True)
        self.driver._device_is_bridge_member('bridge0', 'em0').AndReturn(False)
        self.driver._execute('ifconfig', 'bridge0', 'addm', 'em0',
                             check_exit_code=0, run_as_root=True)
        self.driver._execute('ifconfig', 'em0', 'up', check_exit_code=0,
                             run_as_root=True)
        self.driver._route_list('em0')
        self.driver._delete_routes_from_list(mox.IgnoreArg())
        self.driver._ip_list(mox.IgnoreArg())
        self.driver._delete_ip_from_list(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver._add_ip_from_list(mox.IgnoreArg(), mox.IgnoreArg())
        self.driver._add_routes_from_list(mox.IgnoreArg())

        self.mox.ReplayAll()
        self.driver.FreeBSDBridgeInterfaceDriver.ensure_bridge('bridge0', 'em0')

    def test_device_exists(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        self.driver._execute('ifconfig', 'em0', check_exit_code=False,
                             run_as_root=True).AndReturn(('', ''))
        self.driver._execute('ifconfig', 'eth0', check_exit_code=False,
                             run_as_root=True).AndReturn(
            ('ifconfig: interface eth0 does not exist', '1'))
        self.mox.ReplayAll()
        exists = self.driver._device_exists('em0')
        self.assertEqual(True, exists)
        exists = self.driver._device_exists('eth0')
        self.assertEqual(False, exists)

    def test_device_is_bridge_member(self):
        ifconfig_out = (
            'bridge0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> '
                 'metric 0 mtu 1500\n'
            'ether 02:fd:b9:3e:38:00\n'
            'inet 10.11.12.3 netmask 0xffffff00 broadcast 10.11.12.255\n'
            'nd6 options=9<PERFORMNUD,IFDISABLED>\n'
            'id 00:00:00:00:00:00 priority 32768 hellotime 2 fwddelay 15\n'
            'maxage 20 holdcnt 6 proto rstp maxaddr 2000 timeout 1200\n'
            'root id 00:00:00:00:00:00 priority 32768 ifcost 0 port 0\n'
            'member: vnet0 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n'
            '        ifmaxaddr 0 port 6 priority 128 path cost 2000000\n'
            'member: em0 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n'
            '       ifmaxaddr 0 port 1 priority 128 path cost 2000000\n',
            '0'
        )

        self.mox.StubOutWithMock(self.driver, '_execute')

        self.driver._execute('ifconfig', 'bridge0').AndReturn(ifconfig_out)
        self.driver._execute('ifconfig', 'bridge0').AndReturn(ifconfig_out)

        self.mox.ReplayAll()
        is_member = self.driver._device_is_bridge_member('bridge0', 'em0')
        self.assertEqual(True, is_member)
        is_member = self.driver._device_is_bridge_member('bridge0', 'eth0')
        self.assertEqual(False, is_member)

    def test_route_list(self):
        out = (
            'Routing tables\n\n'
            'Internet:\n'
            'Destination        Gateway            Flags    Refs      Use'
               '   Mtu    Netif Expire\n'
            'default            10.100.0.254       UGS         0  1100615'
               '   1500      em1\n'
            '10.11.12.0/24      link#4             U           0     2316'
               '   1500  bridge0\n'
            '10.11.12.3         link#4             UHS         0        0'
               '  16384      lo0\n'
            '10.100.0.0/16      link#2             U           0 11942365'
               '   1500      em1\n'
            '10.100.2.21        link#2             UHS         0        0'
               '  16384      lo0\n'
            '127.0.0.1          link#3             UH          0     1380'
               '  16384      lo0\n'
            '169.254.169.254    link#3             UH          0        0'
               '  16384      lo0\n'
            '192.168.122.0/24   link#5             U           0        0'
               '   1500   virbr0\n'
            '192.168.122.1      link#5             UHS         0        0'
               '  16384      lo0\n',
            0
        )

        self.mox.StubOutWithMock(self.driver, '_execute')

        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(out)
        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(out)
        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(out)

        self.mox.ReplayAll()
        routes = self.driver._route_list('em1')
        self.assertEqual([['default', '10.100.0.254', 'UGS', '0', '1100615',
                          '1500', 'em1']], routes)
        routes = self.driver._route_list('eth0')
        self.assertEqual([], routes)
        routes = self.driver._route_list('lo0')
        self.assertEqual([], routes)


    def test_delete_routes_from_list(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        route_list = [
            ['default', '10.100.0.254', 'UGS', '0', '1100615', '1500', 'em1'],
            ['default', '10.100.1.254', 'UGS', '0', '1100615', '1500', 'em1']
        ]
        self.driver._execute('route', '-q', 'delete', 'default', '10.100.0.254',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('route', '-q', 'delete', 'default', '10.100.1.254',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )

        self.mox.ReplayAll()
        self.driver._delete_routes_from_list(route_list)
        self.driver._delete_routes_from_list([])

    def test_add_routes_from_list(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        route_list = [
            ['default', '10.100.0.254', 'UGS', '0', '1100615', '1500', 'em1'],
            ['default', '10.100.1.254', 'UGS', '0', '1100615', '1500', 'em1']
        ]
        self.driver._execute('route', '-q', 'add', 'default', '10.100.0.254',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('route', '-q', 'add', 'default', '10.100.1.254',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )

        self.mox.ReplayAll()
        self.driver._add_routes_from_list(route_list)
        self.driver._add_routes_from_list([])

    def test_ip_list(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        out = (
            'em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 '
                'mtu 1500\n'
	        '   options=4219b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,'
                'VLAN_HWCSUM,TSO4,WOL_MAGIC,VLAN_HWTSO>\n'
	        '   ether 00:25:90:d2:ad:60\n'
	        '   inet 192.168.0.1 netmask 0xffffff00 broadcast 192.168.0.255\n'
	        '   nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n'
	        '   media: Ethernet autoselect (1000baseT <full-duplex>)\n'
	        '   status: active\n', ''
        )
        out2 = (
            'em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 '
                'mtu 1500\n'
	        '   options=4219b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,'
                'VLAN_HWCSUM,TSO4,WOL_MAGIC,VLAN_HWTSO>\n'
	        '   ether 00:25:90:d2:ad:60\n'
	        '   inet 192.168.0.1 netmask 0xffffff00 broadcast 192.168.0.255\n'
            '   inet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255\n'
	        '   nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n'
	        '   media: Ethernet autoselect (1000baseT <full-duplex>)\n'
	        '   status: active\n', ''
        )
        self.driver._execute('ifconfig', 'em0').AndReturn(out)
        self.driver._execute('ifconfig', 'em0').AndReturn(out2)

        self.mox.ReplayAll()
        ip_list = self.driver._ip_list('em0')
        self.assertEqual([['inet', '192.168.0.1', 'netmask', '0xffffff00',
                         'broadcast', '192.168.0.255']], ip_list)
        ip_list = self.driver._ip_list('em0')
        expected = [
            ['inet', '192.168.0.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.0.255'],
            ['inet', '192.168.1.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.1.255']
        ]
        self.assertEqual(expected, ip_list)

    def test_delete_ip_from_list(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        ip_list = [
            ['inet', '192.168.0.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.0.255'],
            ['inet', '192.168.1.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.1.255']
        ]
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'delete', check_exit_code=0,
                             run_as_root=True).AndReturn(('', ''))
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.1.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.1.255', 'delete', check_exit_code=0,
                             run_as_root=True).AndReturn(('', ''))

        self.mox.ReplayAll()
        self.driver._delete_ip_from_list(ip_list, 'em0')
        self.driver._delete_ip_from_list([], 'em0')

    def test_add_ip_from_list(self):
        self.mox.StubOutWithMock(self.driver, '_execute')

        ip_list = [
            ['inet', '192.168.0.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.0.255'],
            ['inet', '192.168.1.1', 'netmask', '0xffffff00', 'broadcast',
             '192.168.1.255']
        ]
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'add', check_exit_code=0,
                             run_as_root=True).AndReturn(('', ''))
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.1.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.1.255', 'add', check_exit_code=0,
                             run_as_root=True).AndReturn(('', ''))

        self.mox.ReplayAll()
        self.driver._add_ip_from_list(ip_list, 'em0')
        self.driver._add_ip_from_list([], 'em0')

    def test_initialize_gateway(self):
        self.mox.StubOutWithMock(self.driver, '_execute')
        self.mox.StubOutWithMock(self.driver, '_address_to_cidr')

        self.driver._execute('sysctl', 'net.inet.ip.forwarding=1',
                      run_as_root=True).AndReturn(
            ('net.inet.ip.forwarding: 1 -> 1', '')
        )
        self.driver._execute('ifconfig', 'em0').AndReturn((
            'em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 '
                'mtu 1500\n'
	        '   options=4219b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,'
                'VLAN_HWCSUM,TSO4,WOL_MAGIC,VLAN_HWTSO>\n'
	        '   ether 00:25:90:d2:ad:60\n'
	        '   inet 192.168.0.1 netmask 0xffffff00 broadcast 192.168.0.255\n'
	        '   nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n'
	        '   media: Ethernet autoselect (1000baseT <full-duplex>)\n'
	        '   status: active\n', '')
        )
        self.driver._address_to_cidr('192.168.0.1', '0xffffff00').AndReturn(
            '192.168.0.1/24'
        )
        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(
            ('default 192.168.0.254 UGS 0 844794 1500 em0\n'
             '192.168.0.0/24 link#2 U 0 11084639 1500 em0\n',
             '')
        )
        self.driver._execute('route', '-q', 'delete', 'default',
                             '192.168.0.254', check_exit_code=0,
                             run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'delete', check_exit_code=0,
                             run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.1.1/24',
                             'broadcast', '192.168.1.255', 'add',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._address_to_cidr('192.168.0.1', '0xffffff00').AndReturn(
            '192.168.0.1/24'
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'add', check_exit_code=0,
                             run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('route', '-q', 'add', 'default', '192.168.0.254',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )

        network = {
            'dhcp_server': '192.168.1.1',
            'cidr': '192.168.1.0/24',
            'broadcast': '192.168.1.255',
            'cidr_v6': '2001:db8::/64'
        }

        self.mox.ReplayAll()
        self.driver.initialize_gateway_device('em0', network)

    def test_initialize_gateway_no_route_reset(self):
        self.mox.StubOutWithMock(self.driver, '_execute')
        self.mox.StubOutWithMock(self.driver, '_address_to_cidr')

        self.driver._execute('sysctl', 'net.inet.ip.forwarding=1',
                      run_as_root=True).AndReturn(
            ('net.inet.ip.forwarding: 1 -> 1', '')
        )
        self.driver._execute('ifconfig', 'em0').AndReturn((
            'em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 '
                'mtu 1500\n'
	        '   options=4219b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,'
                'VLAN_HWCSUM,TSO4,WOL_MAGIC,VLAN_HWTSO>\n'
	        '   ether 00:25:90:d2:ad:60\n'
	        '   inet 192.168.0.1 netmask 0xffffff00 broadcast 192.168.0.255\n'
	        '   nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n'
	        '   media: Ethernet autoselect (1000baseT <full-duplex>)\n'
	        '   status: active\n', '')
        )
        self.driver._address_to_cidr('192.168.0.1', '0xffffff00').AndReturn(
            '192.168.0.1/24'
        )
        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(
            ('192.168.0.0/24 link#2 U 0 11084639 1500 em0\n', '')
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'delete', check_exit_code=0,
                             run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.1.1/24',
                             'broadcast', '192.168.1.255', 'add',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )
        self.driver._address_to_cidr('192.168.0.1', '0xffffff00').AndReturn(
            '192.168.0.1/24'
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.0.1',
                             'netmask', '0xffffff00', 'broadcast',
                             '192.168.0.255', 'add', check_exit_code=0,
                             run_as_root=True).AndReturn(
            ('', '')
        )

        network = {
            'dhcp_server': '192.168.1.1',
            'cidr': '192.168.1.0/24',
            'broadcast': '192.168.1.255',
            'cidr_v6': '2001:db8::/64'
        }

        self.mox.ReplayAll()
        self.driver.initialize_gateway_device('em0', network)

    def test_initialize_gateway_no_ip_set(self):
        self.mox.StubOutWithMock(self.driver, '_execute')
        self.mox.StubOutWithMock(self.driver, '_address_to_cidr')

        self.driver._execute('sysctl', 'net.inet.ip.forwarding=1',
                      run_as_root=True).AndReturn(
            ('net.inet.ip.forwarding: 1 -> 1', '')
        )
        self.driver._execute('ifconfig', 'em0').AndReturn((
            'em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 '
                'mtu 1500\n'
	        '   options=4219b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,'
                'VLAN_HWCSUM,TSO4,WOL_MAGIC,VLAN_HWTSO>\n'
	        '   ether 00:25:90:d2:ad:60\n'
	        '   nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n'
	        '   media: Ethernet autoselect (1000baseT <full-duplex>)\n'
	        '   status: active\n', '')
        )
        self.driver._execute('netstat', '-nrW', '-f', 'inet').AndReturn(
            ('192.168.0.0/24 link#2 U 0 11084639 1500 em0\n', '')
        )
        self.driver._execute('ifconfig', 'em0', 'inet', '192.168.1.1/24',
                             'broadcast', '192.168.1.255', 'add',
                             check_exit_code=0, run_as_root=True).AndReturn(
            ('', '')
        )

        network = {
            'dhcp_server': '192.168.1.1',
            'cidr': '192.168.1.0/24',
            'broadcast': '192.168.1.255',
            'cidr_v6': '2001:db8::/64'
        }

        self.mox.ReplayAll()
        self.driver.initialize_gateway_device('em0', network)
