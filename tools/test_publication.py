"""Consumer-format and monotonic-publication regressions; no network/module execution."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from convert_runtime import compile_rules
from publish_runtime import CAPABILITIES,publish,validate,read_manifest
from zuiopt_format import dump_rules,parse_rules

ROOT=Path(__file__).resolve().parents[1]

class PublicationTest(unittest.TestCase):
    def setUp(self):
        model=json.loads((ROOT/'analysis/latest.json').read_bytes())
        model['runtime_masks_sm8650']={str(i):dict(zip(('general','C1','C2'),row)) for i,row in enumerate(((124,28,128),(252,252,252),(252,252,128)))}
        self.rules,_=compile_rules(model,[],CAPABILITIES)
        self.meta=dict(version='Kana',release_published_at='2026-09-18T20:24:34Z')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.out=Path(self.temp.name)/'output'
        self.first=publish(self.out,self.rules,self.meta,'a'*40)['manifest']

    def test_current_consumer_and_raw_inheritance(self):
        cfg=validate(self.first,(self.out/'rules.conf').read_bytes())
        self.assertEqual((self.first['schema'],self.first['rulesSchema']),(2,3))
        self.assertEqual(len(cfg['packages']),333)
        self.assertEqual((cfg['mode'],cfg['rt']),(0,0))
        self.assertTrue(all(p['runtime'][:2]==(-1,-1) for p in cfg['profiles'].values()))
        self.assertIn('marker-double',self.first['requiredCapabilities'])
        self.assertEqual((self.out/'rules.conf').read_bytes(),dump_rules(parse_rules(self.rules)))

    def test_unchanged_content_does_not_mint_revision(self):
        old=(self.out/'latest.json').read_bytes()
        self.assertEqual(publish(self.out,self.rules,self.meta,'b'*40)['result'],'NO_RULE_CONTENT_CHANGE')
        self.assertEqual((self.out/'latest.json').read_bytes(),old)
        cfg=parse_rules(self.rules);cfg['mode']=1
        second=publish(self.out,dump_rules(cfg),self.meta,'b'*40)['manifest']
        self.assertEqual(second['revision'],2)
        self.assertEqual(second['sourceCommit'],'b'*40)
        self.assertEqual(json.loads((self.out.parent/'history/schema3-releases/1/latest.json').read_bytes()),self.first)

    def test_tamper_bounds_platform_and_capabilities_rejected(self):
        body=(self.out/'rules.conf').read_bytes()
        for key,value in [('rulesSha256','0'*64),('rulesSize',1),('targetTopology','0-3'),('targetSoC','SM8550'),('revision',True),('rulesSchema',2),('sourceCommit','invalid'),('requiredCapabilities',[])]:
            with self.subTest(key=key),self.assertRaises(ValueError):validate({**self.first,key:value},body)
        with self.assertRaises(ValueError):validate(self.first,body[:-1])
        self.out.joinpath('latest.json').write_text('{"schema":2,"schema":2}')
        with self.assertRaisesRegex(ValueError,'duplicate'):read_manifest(self.out/'latest.json')

    def test_failure_keeps_manifest_last_and_mixed_download_rejected(self):
        cfg=parse_rules(self.rules);cfg['rt']=1
        body=dump_rules(cfg);old=(self.out/'latest.json').read_bytes()
        from publish_runtime import replace
        def fail_last(path,data):
            if path==self.out/'latest.json':raise OSError('injected manifest replace failure')
            replace(path,data)
        with patch('publish_runtime.replace',side_effect=fail_last),self.assertRaises(OSError):publish(self.out,body,self.meta,'b'*40)
        self.assertEqual((self.out/'latest.json').read_bytes(),old)
        with self.assertRaises(ValueError):validate(self.first,(self.out/'rules.conf').read_bytes())

    def test_legacy_analysis_migration_not_schema2_pack_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'output';out.mkdir();out.joinpath('latest.json').write_text('{"status":"ANALYSIS_ONLY"}')
            self.assertEqual(publish(out,self.rules,self.meta,'c'*40)['manifest']['rulesSchema'],3)
        cfg=parse_rules(self.rules);cfg.pop('schema');cfg.pop('mode');cfg.pop('rt')
        for profile in cfg['profiles'].values():profile.pop('runtime')
        with tempfile.TemporaryDirectory() as tmp,self.assertRaisesRegex(ValueError,'Schema3'):publish(Path(tmp)/'output',dump_rules(cfg),self.meta,'c'*40)

if __name__=='__main__':unittest.main()
