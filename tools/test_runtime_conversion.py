import copy,json,unittest
from pathlib import Path
from convert_runtime import compile_rules,BASE_CAPABILITIES
from extract_asoulopt import QUALIFIED_BINARY

class ConversionTest(unittest.TestCase):
    def setUp(self):
        self.model=json.loads((Path(__file__).resolve().parents[1]/'analysis/latest.json').read_text())
        self.model['runtime_masks_sm8650']={str(i):dict(zip(('general','C1','C2'),v)) for i,v in enumerate(((124,28,128),(252,252,252),(252,252,128)))}
        self.cap=BASE_CAPABILITIES|{'mode0','mode1','mode2','marker-dummy','marker-double','walt-boost-restorable'}
    def test_order_markers_and_deterministic_expansion(self):
        first=self.model['packages'][0]['pattern'];name=first+'.installed'
        text,report=compile_rules(self.model,[name,'org.unmatched.app'],self.cap)
        self.assertIn(('package exact '+name+' ').encode(),text);self.assertNotIn(b'package exact org.unmatched.app ',text)
        self.assertIn(b'preset dummy\n',text);self.assertIn(b'preset double\n',text)
        self.assertNotIn(b'contains "__DummyMain"',text);self.assertNotIn(b'contains "__DoubleMain"',text)
        self.assertEqual((text,report),compile_rules(self.model,['org.unmatched.app',name,name],self.cap))
    def test_unknown_identity_mask_and_missing_capability(self):
        for key,value in [('qualified',False),('binary_sha256','0'*64),('package_count',332)]:
            with self.assertRaises(ValueError):compile_rules({**self.model,key:value},[],self.cap)
        bad=copy.deepcopy(self.model);bad['runtime_masks_sm8650']['1']['C2']=128
        with self.assertRaises(ValueError):compile_rules(bad,[],self.cap)
        with self.assertRaisesRegex(ValueError,'unsupported required'):compile_rules(self.model,[],self.cap,2,1)
        with self.assertRaisesRegex(ValueError,'unsupported required'):compile_rules(self.model,[],self.cap-{'marker-double'})
    def test_mode2_rt1_named_capability_and_raw_inheritance(self):
        text,report=compile_rules(self.model,[],self.cap|{'walt-reduce-restorable'},2,1)
        self.assertIn(b'runtime_defaults 2 1\n',text)
        self.assertIn('walt-reduce-restorable',report['required_capabilities'])
        self.assertNotIn(b'walt-reduce-restorable',text)
        for line in text.splitlines():
            if line.startswith(b'runtime '):self.assertEqual(line.split()[2:4],[b'-1',b'-1'])
    def test_installed_update_and_uninstall(self):
        name=self.model['packages'][0]['pattern']+'.variant';before,_=compile_rules(self.model,[],self.cap);after,_=compile_rules(self.model,[name],self.cap)
        self.assertNotEqual(before,after);self.assertEqual(before,compile_rules(self.model,[],self.cap)[0])
        self.assertEqual(before,compile_rules(self.model,['android'],self.cap)[0])
        with self.assertRaises(ValueError):compile_rules(self.model,['not a package'],self.cap)
if __name__=='__main__':unittest.main()
