"""Publish one Schema3 body and the existing App download-manifest protocol."""
from pathlib import Path
import datetime,json,os,re,tempfile
from convert_runtime import BASE_CAPABILITIES
from fetch_asoulopt import require,sha256
from zuiopt_format import MAX_RULES,parse_rules,dump_rules

MAX_REVISION=9007199254740991
CAPABILITIES=BASE_CAPABILITIES|{'mode0','mode1','mode2','marker-dummy','marker-double','walt-boost-restorable','walt-reduce-restorable'}
FIELDS={'schema','revision','source','sourceVersion','sourceDate','sourceCommit','targetSoC','targetTopology','rulesSchema','rulesSha256','rulesSize','requiredCapabilities'}

def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')

def capabilities(config):
    needed=set(BASE_CAPABILITIES)
    for profile in config['profiles'].values():
        mode,rt,placement,marker=profile['runtime']
        mode=config['mode'] if mode<0 else mode;rt=config['rt'] if rt<0 else rt
        needed.add('mode'+str(mode))
        if mode==2 and placement=='preset':needed.add('walt-reduce-restorable' if rt else 'walt-boost-restorable')
        if marker!='none':needed.add('marker-'+marker)
    if not config['profiles']:needed.add('mode'+str(config['mode']))
    return sorted(needed)

def validate(manifest,rules):
    require(set(manifest)==FIELDS,'manifest fields')
    require(type(manifest['schema']) is int and manifest['schema']==2 and type(manifest['rulesSchema']) is int and manifest['rulesSchema']==3,'Schema3 publication required')
    require(type(manifest['revision']) is int and 1<=manifest['revision']<=MAX_REVISION,'revision bound')
    require(manifest['targetSoC']=='SM8650' and manifest['targetTopology']=='0-7','target platform')
    for key,pattern in (('source',r'[A-Za-z0-9_.:/-]{1,128}'),('sourceVersion',r'[A-Za-z0-9_.+-]{1,64}'),('sourceDate',r'[0-9]{4}-[0-9]{2}-[0-9]{2}'),('sourceCommit',r'[0-9a-f]{40}'),('rulesSha256',r'[0-9a-f]{64}')):
        require(isinstance(manifest[key],str) and re.fullmatch(pattern,manifest[key]),key+' bound')
    datetime.date.fromisoformat(manifest['sourceDate'])
    require(type(manifest['rulesSize']) is int and manifest['rulesSize']==len(rules) and 0<len(rules)<=MAX_RULES and sha256(rules)==manifest['rulesSha256'],'rules integrity')
    require(len(encode(manifest))<=2048,'App manifest limit')
    config=parse_rules(rules)
    require(config.get('schema')==3 and not config['debug'] and dump_rules(config)==rules,'canonical Schema3/debug contract')
    require(all(p[0]=='exact' for p in config['packages']),'library package matching contract')
    require(manifest['requiredCapabilities']==capabilities(config) and set(manifest['requiredCapabilities'])<=CAPABILITIES,'required capabilities/content mismatch')
    return config

def read_manifest(path):
    data=path.read_bytes();require(0<len(data)<=2048,'manifest size')
    def unique(pairs):
        result={}
        for key,value in pairs:require(key not in result,'duplicate manifest key');result[key]=value
        return result
    return json.loads(data.decode('ascii'),object_pairs_hook=unique)

def replace(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.'+path.name+'-',delete=False) as stream:
        temp=Path(stream.name)
        try:stream.write(data);stream.flush();os.fsync(stream.fileno())
        except BaseException:temp.unlink(missing_ok=True);raise
    try:os.replace(temp,path)
    finally:temp.unlink(missing_ok=True)

def publish(output,rules,meta,commit):
    output=Path(output);config=parse_rules(rules)
    require(config.get('schema')==3,'Schema3 publication required')
    rules=dump_rules(config);previous=None
    if (output/'rules.conf').exists():
        require((output/'latest.json').exists(),'existing body has no manifest')
        previous=read_manifest(output/'latest.json');validate(previous,(output/'rules.conf').read_bytes())
        if previous['rulesSha256']==sha256(rules):return dict(result='NO_RULE_CONTENT_CHANGE',manifest=previous)
    elif (output/'latest.json').exists():
        legacy=json.loads((output/'latest.json').read_bytes())
        require(legacy.get('status')=='ANALYSIS_ONLY' and 'rulesSchema' not in legacy,'unrecognized publication baseline')
    revision=previous['revision']+1 if previous else 1
    manifest=dict(schema=2,revision=revision,source='nakixii/Magisk_AsoulOpt',sourceVersion=meta['version'],sourceDate=meta['release_published_at'][:10],sourceCommit=commit,targetSoC='SM8650',targetTopology='0-7',rulesSchema=3,rulesSha256=sha256(rules),rulesSize=len(rules),requiredCapabilities=capabilities(parse_rules(rules)))
    validate(manifest,rules)
    # Keep every published revision; failures never replace a known-good manifest first.
    archive=output.parent/'history/schema3-releases'/str(revision)
    require(not archive.exists(),'publication revision archive conflict')
    replace(archive/'rules.conf',rules);replace(archive/'latest.json',encode(manifest))
    replace(output/'rules.conf',rules);replace(output/'latest.json',encode(manifest))
    return dict(result='SCHEMA3_PUBLISHED',manifest=manifest)
