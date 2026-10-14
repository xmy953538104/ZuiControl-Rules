"""Canonical ZuiControl parser/serializer subset; provenance in reference/schema3_protocol.json."""
import json,re,shlex
MAX_RULES=65536
LABEL=re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
PACKAGE=re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")

def need(ok,reason):
    if not ok: raise ValueError(reason)

def mask(text):
    need(bool(re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*',text)),'CPU syntax')
    bits=0
    for part in text.split(','):
        ends=list(map(int,part.split('-')));a=ends[0];b=ends[-1]
        need(0<=a<=b<8,'SM8650 CPU bound')
        for c in range(a,b+1): bits|=1<<c
    return bits

def validate_glob(pattern):
    need(0<len(pattern)<=64 and all(32<=ord(c)<127 and c!='\\' for c in pattern),'glob characters/size')
    i=0
    while i<len(pattern):
        c=pattern[i]
        if c=='[':
            i+=1;count=0
            while i<len(pattern) and pattern[i]!=']':
                a=pattern[i];need(a not in '[\\!^','glob class')
                if i+1<len(pattern) and pattern[i+1]=='-':
                    need(i+2<len(pattern) and pattern[i+2] not in '][\\' and a<=pattern[i+2],'glob range')
                    i+=2
                count+=1;i+=1
            need(i<len(pattern) and count>0,'glob class closing')
        else: need(c!=']','unpaired glob close')
        i+=1

def parse_rules(data):
    if isinstance(data,str): data=data.encode('utf8')
    need(0<len(data)<=MAX_RULES and b'\0' not in data,'config size/NUL')
    text=data.decode('ascii');profiles={};packages=[];headers={};runtime_defaults=None;runtime_profiles=set()
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'): continue
        need(len(line)<1024,'line bound')
        t=shlex.split(line,comments=False,posix=True);k=t[0]
        if k in ('schema','enabled','debug'):
            need(len(t)==2 and k not in headers,'header syntax/duplicate')
            need(t[1] in (('2','3') if k=='schema' else ('true','false')),'header value');headers[k]=t[1]
        elif k=='runtime_defaults':
            need(len(t)==3 and runtime_defaults is None and t[1] in ('0','1','2') and t[2] in ('0','1'),'runtime defaults')
            runtime_defaults=(int(t[1]),int(t[2]))
        elif k=='runtime':
            need(len(t)==6 and t[1] in profiles and t[1] not in runtime_profiles,'runtime profile/duplicate')
            need(t[2] in ('-1','0','1','2') and t[3] in ('-1','0','1') and t[4] in ('explicit','preset') and t[5] in ('none','dummy','double'),'runtime profile values')
            need(t[4]=='preset' or t[5]=='none','marker requires mode preset')
            profiles[t[1]]['runtime']=(int(t[2]),int(t[3]),t[4],t[5]);runtime_profiles.add(t[1])
        elif k=='profile':
            need(len(t)==3 and LABEL.fullmatch(t[1]) and t[1] not in profiles,'profile syntax/duplicate')
            profiles[t[1]]={'mask':mask(t[2]),'rules':[]}
        elif k=='thread':
            need(len(t)==8 and t[1] in profiles and LABEL.fullmatch(t[2]),'thread syntax')
            _,name,group,kind,pattern,selector,priority,cpu=t
            need(kind in ('exact','prefix','contains','glob') and (pattern or kind=='contains') and len(pattern)<=64,'thread match')
            need(all(32<=ord(c)<127 for c in pattern),'thread characters')
            if kind=='glob': validate_glob(pattern)
            need(selector=='selector=all' or re.fullmatch(r'selector=rank:[0-9]+',selector),'explicit selector')
            rank=0 if selector=='selector=all' else int(selector.split(':')[1]);need(selector=='selector=all' or 1<=rank<=1024,'rank bound')
            need(re.fullmatch(r'-?[0-9]+',priority) is not None,'priority syntax');priority=int(priority);need(-2147483648<=priority<=2147483647,'priority bound')
            rule=(group,kind,pattern,rank,priority,mask(cpu))
            for old in profiles[name]['rules']:
                need(old[4]!=priority and (old[0]!=group or (old[3],old[5])==(rank,rule[5])),'thread priority/group conflict')
            profiles[name]['rules'].append(rule)
        elif k=='package':
            need(len(t)==5 and t[1] in ('exact','prefix','contains') and LABEL.fullmatch(t[2]) and t[3] in profiles,'package syntax')
            need(t[1]!='exact' or PACKAGE.fullmatch(t[2]),'package name')
            need(re.fullmatch(r'-?[0-9]+',t[4]) is not None,'package priority syntax');priority=int(t[4]);need(-2147483648<=priority<=2147483647,'priority bound')
            need(all(p[3]!=priority and p[:2]!=(t[1],t[2]) for p in packages),'package duplicate/priority conflict')
            packages.append((t[1],t[2],t[3],priority))
        else: raise ValueError('unknown directive '+k)
        need(len(profiles)<=64 and len(packages)<=512,'config bound')
    need(headers.get('schema') in ('2','3') and 'enabled' in headers,'schema/enabled required')
    need(headers['schema']=='3' or (runtime_defaults is None and not runtime_profiles),'runtime requires schema 3')
    for profile in profiles.values():
        need(len(profile['rules'])<=32,'rule count');profile['rules'].sort(key=lambda r:-r[4])
    packages.sort(key=lambda p:-p[3])
    result=dict(profiles=profiles,packages=packages,enabled=headers['enabled']=='true',debug=headers.get('debug')=='true')
    if headers['schema']=='3':
        result.update(schema=3,mode=(runtime_defaults or (0,0))[0],rt=(runtime_defaults or (0,0))[1])
        for p in profiles.values():p.setdefault('runtime',(-1,-1,'explicit','none'))
    return result

def cpu_text(bits): return ','.join(str(n) for n in range(8) if bits&(1<<n))

def dump_rules(config):
    runtime=config.get('schema')==3 or any('runtime' in p for p in config['profiles'].values())
    lines=['schema '+('3' if runtime else '2'),'enabled '+str(config['enabled']).lower(),'debug '+str(config.get('debug',False)).lower()]
    if runtime:lines.append(f'runtime_defaults {config.get("mode",0)} {config.get("rt",0)}')
    for name,p in sorted(config['profiles'].items()):
        lines.append('profile '+name+' '+cpu_text(p['mask']))
        if runtime:
            mode,rt,placement,marker=p.get('runtime',(-1,-1,'explicit','none'))
            lines.append(f'runtime {name} {mode} {rt} {placement} {marker}')
        for group,kind,pattern,rank,priority,bits in p['rules']:
            lines.append(f'thread {name} {group} {kind} {json.dumps(pattern)} selector={"rank:"+str(rank) if rank else "all"} {priority} {cpu_text(bits)}')
    for kind,package,name,priority in config['packages']: lines.append(f'package {kind} {package} {name} {priority}')
    data=('\n'.join(lines)+'\n').encode('ascii');parse_rules(data);return data
