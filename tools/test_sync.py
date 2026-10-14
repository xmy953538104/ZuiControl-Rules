"""Use local bare repositories to verify forward sync and divergence preservation."""
from pathlib import Path
import subprocess,tempfile,unittest
from sync_gitee import sync

class SyncTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.target=self.root/'target';self.work=self.root/'work'
        for path in (self.source,self.target):self.git(self.root,'init','--bare','--initial-branch=main',path)
        self.git(self.root,'clone',self.source,self.work)
        self.git(self.work,'config','user.name','fixture');self.git(self.work,'config','user.email','fixture@example.invalid')
        self.commit('initial');self.git(self.work,'push','origin','main')

    def git(self,repo,*args):
        return subprocess.check_output(['git',*map(str,args)],cwd=repo,stderr=subprocess.DEVNULL,text=True).strip()

    def commit(self,text):
        (self.work/'rules.conf').write_text(text+'\n');self.git(self.work,'add','rules.conf');self.git(self.work,'commit','-m',text)

    def test_empty_forward_and_unchanged(self):
        first=sync(self.work,str(self.target));self.assertTrue(first['changed'])
        self.assertFalse(sync(self.work,str(self.target))['changed'])
        self.commit('next');self.git(self.work,'push','origin','main')
        result=sync(self.work,str(self.target));self.assertTrue(result['changed'])
        self.assertEqual(result['gitee_head'],self.git(self.source,'rev-parse','main'))
        self.assertFalse(result['force_push']);self.assertEqual(result['deleted_refs'],0)

    def test_divergent_target_is_preserved(self):
        sync(self.work,str(self.target));other=self.root/'other';self.git(self.root,'clone',self.target,other)
        self.git(other,'config','user.name','fixture');self.git(other,'config','user.email','fixture@example.invalid')
        (other/'independent').write_text('Owner independent content');self.git(other,'add','independent');self.git(other,'commit','-m','independent');self.git(other,'push','origin','main')
        previous=self.git(self.target,'rev-parse','main')
        self.commit('source-next');self.git(self.work,'push','origin','main')
        with self.assertRaisesRegex(ValueError,'diverged'):sync(self.work,str(self.target))
        self.assertEqual(self.git(self.target,'rev-parse','main'),previous)

if __name__=='__main__':unittest.main()
