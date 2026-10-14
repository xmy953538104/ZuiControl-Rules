"""Fast-forward main only; never mirror-delete refs or force divergent Gitee history."""
from pathlib import Path
import json,os,subprocess,tempfile
from fetch_asoulopt import require

TARGET='https://gitee.com/xmy953538104/ZuiControl-Rules.git'
BRANCH='refs/heads/main'

def git(repo,*args,env=None,allowed=(0,)):
    result=subprocess.run(['git',*map(str,args)],cwd=repo,env=env,capture_output=True,timeout=90)
    if result.returncode not in allowed:
        error=result.stderr.decode('utf8','replace')
        token=(env or os.environ).get('GITEE_SYNC_TOKEN','')
        if token:error=error.replace(token,'[REDACTED]')
        raise RuntimeError('git operation failed: '+error[-2000:])
    return result.returncode,result.stdout.decode().strip()

def sync(repo,target=TARGET,env=None):
    repo=Path(repo)
    git(repo,'fetch','--no-tags','origin',BRANCH,env=env)
    _,source=git(repo,'rev-parse','FETCH_HEAD',env=env)
    _,rows=git(repo,'ls-remote','--heads',target,BRANCH,env=env)
    previous=rows.split()[0] if rows else ''
    if previous:
        git(repo,'fetch','--no-tags',target,BRANCH,env=env)
        _,observed=git(repo,'rev-parse','FETCH_HEAD',env=env)
        require(previous==observed,'Gitee changed during inspection; retry from fresh state')
        code,_=git(repo,'merge-base','--is-ancestor',previous,source,env=env,allowed=(0,1))
        require(code==0,'Gitee diverged; resolve independent commits, no force push')
    if previous!=source:git(repo,'push',target,source+':'+BRANCH,env=env)
    _,rows=git(repo,'ls-remote','--heads',target,BRANCH,env=env)
    require(rows.split()[0]==source,'Gitee readback does not match requested source')
    return dict(status='PASS_FAST_FORWARD_MAIN_SYNC',source_head=source,previous_gitee_head=previous,gitee_head=source,changed=previous!=source,force_push=False,deleted_refs=0)

def main():
    require(bool(os.environ.get('GITEE_SYNC_TOKEN')),'GITEE_SYNC_TOKEN is required in GitHub repository Secrets')
    with tempfile.TemporaryDirectory(prefix='gitee-askpass-') as directory:
        helper=Path(directory)/'askpass.sh'
        helper.write_text('#!/bin/sh\ncase "$1" in\n*Username*) printf "%s\\n" "xmy953538104" ;;\n*) printf "%s\\n" "$GITEE_SYNC_TOKEN" ;;\nesac\n',encoding='utf8',newline='\n')
        helper.chmod(0o700)
        # Secret stays in the Actions environment, never in a URL, file or Git config value.
        env=dict(os.environ,GIT_ASKPASS=str(helper),GIT_TERMINAL_PROMPT='0',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='credential.helper',GIT_CONFIG_VALUE_0='',GIT_TRACE='0',GIT_TRACE_CURL='0')
        print(json.dumps(sync(Path.cwd(),env=env),sort_keys=True))

if __name__=='__main__':main()
