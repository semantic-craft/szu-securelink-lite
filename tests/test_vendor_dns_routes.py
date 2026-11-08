import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

spec=importlib.util.spec_from_file_location('vendor_dns_routes',Path(__file__).resolve().parents[1]/'scripts/vendor_dns_routes.py')
routes=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=routes
spec.loader.exec_module(routes)
from test_network_plan import capture

class VendorDNSRoutesTests(unittest.TestCase):
    def derive(self,c): return routes.derive(json.dumps(c).encode())
    def test_only_host_candidates_and_no_authority(self):
        c=capture();before=copy.deepcopy(c)
        result=self.derive(c)
        self.assertEqual(result.issues,())
        self.assertEqual([(r.destination,r.gateway) for r in result.candidates],[('10.30.0.53/32','10.20.0.1')])
        self.assertFalse(result.execution_authorized)
        self.assertEqual(c,before)
        self.assertNotIn('10.30.',repr(result))
    def test_absent_mtu_and_global_dns_are_not_silently_authorized(self):
        c=capture();c['mtu']=None;c['dns']['servers'][0]['domains']=[]
        result=self.derive(c)
        self.assertEqual(len(result.candidates),1)
        self.assertFalse(result.execution_authorized)
    def test_duplicate_dns_and_existing_host_route(self):
        c=capture();c['dns']['servers'][0]['addresses']*=2
        result=self.derive(c);self.assertEqual(len(result.candidates),1);self.assertEqual(result.deduplicated,1)
        c['routes'].append({'address':'10.30.0.53','prefixLength':32,'metric':-1,'ipv6':False})
        result=self.derive(c);self.assertEqual(result.candidates,());self.assertEqual(result.deduplicated,2)
        c['routes'][-1]['metric']=1
        self.assertIn('dns-route-metric-conflict',self.derive(c).issues)
    def test_conflicts_fail_without_partial_candidates(self):
        for address in ['10.20.0.1','10.20.0.2','198.51.100.4']:
            c=capture();c['dns']['servers'][0]['addresses'].append({'address':address,'port':0})
            r=self.derive(c);self.assertEqual(r.candidates,());self.assertIn('dns-endpoint-conflict',r.issues)
        c=capture();c['excludedRoutes']=[c['routes'][0]]
        self.assertIn('dns-excluded-route-conflict',self.derive(c).issues)
    def test_no_guessing_gateway_or_ipv6_or_source(self):
        c=capture();c['addresses'][0]['gateway']=''
        self.assertIn('missing-or-ambiguous-ipv4-vpn-gateway',self.derive(c).issues)
        c=capture();other=copy.deepcopy(c['addresses'][0]);other['gateway']='10.20.0.3';c['addresses'].append(other)
        self.assertIn('missing-or-ambiguous-ipv4-vpn-gateway',self.derive(c).issues)
        c=capture();c['dns']['servers'][0]['addresses'].append({'address':'2001:db8::53','port':0})
        self.assertIn('unsupported-ipv6-dns-route',self.derive(c).issues)
        c=capture();c['dns']['fromDhcp']=False
        self.assertIn('unsupported-dns-source',self.derive(c).issues)
    def test_malformed_bounded_raw_and_strict_fields(self):
        for raw in [b'{}',b'null',b'{"x":1,"x":2}',b'{"x":NaN}',b'['*2000,b'x'*65537,b'\xff']:
            self.assertEqual(routes.derive(raw).issues,('invalid-capture',))
        for mutate in [lambda c:c.update({'secret':'NO-LEAK'}),lambda c:c['dns'].update({'secret':'NO-LEAK'}),lambda c:c['dns']['servers'][0]['addresses'][0].update({'port':True}),lambda c:c['addresses'][0].update({'ipv6':0})]:
            c=capture();mutate(c);r=self.derive(c);self.assertEqual(r.issues,('invalid-capture',));self.assertNotIn('NO-LEAK',repr(r))
        for address in ['127.0.0.1','0.0.0.0','169.254.1.1','224.0.0.1','255.255.255.255','1.2.3.4;bad']:
            c=capture();c['dns']['servers'][0]['addresses'][0]['address']=address
            self.assertEqual(self.derive(c).issues,('invalid-capture',))
    def test_no_dns_needs_no_guessed_gateway(self):
        c=capture();c['dns']['servers']=[];c['addresses']=[]
        self.assertEqual(self.derive(c).candidates,())
        self.assertEqual(self.derive(c).issues,())

if __name__=='__main__':unittest.main()
