"""Offline reviewed Kana -> Schema3; publication and module execution are absent."""
import json,re
from extract_asoulopt import QUALIFIED_BINARY
from fetch_asoulopt import require

BASE_CAPABILITIES={'schema3','category-ranking','runtime-inheritance','owned-rt-recovery'}
def required_capabilities(mode,rt,markers):
    required=BASE_CAPABILITIES|{'mode'+str(mode)}
    if mode==2:required.add('walt-reduce-restorable' if rt else 'walt-boost-restorable')
    required|={'marker-'+marker for marker in markers if marker!='none'}
    return required

def compile_rules(model,installed,capabilities,mode=0,rt=0):
    require(model.get('qualified') is True and model.get('binary_sha256')==QUALIFIED_BINARY,'unreviewed original ELF')
    require(mode in (0,1,2) and rt in (0,1),'mode/rt range')
    masks=model.get('runtime_masks_sm8650',{})
    require([(masks.get(str(i),{}).get('general'),masks.get(str(i),{}).get('C1'),masks.get(str(i),{}).get('C2')) for i in range(3)]==[(124,28,128),(252,252,252),(252,252,128)],'reviewed mask computation required')
    require(model.get('package_count')==333 and model.get('template_count')==29,'reviewed constructor shape')
    packages=model['packages'];templates=model['templates']
    require(len(packages)==333 and len(templates)==29,'neutral model count')
    ordered=sorted(packages,key=lambda row:row['resolution_order'])
    require([r['resolution_order'] for r in ordered]==list(range(333)),'first-match order')
    label=re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+')
    require(all(isinstance(p,str) and (p=='android' or label.fullmatch(p)) for p in installed),'installed package names')
    # Include declared names and expand installed names by the original ordered strstr.
    names=sorted((set(installed)-{'android'})|{r['pattern'] for r in ordered});mappings=[];ambiguities=[]
    for name in names:
        hits=[r for r in ordered if r['pattern'] in name]
        if not hits:continue
        mappings.append((name,hits[0]['template']))
        if len(hits)>1:ambiguities.append(dict(package=name,chosen=hits[0]['pattern'],candidates=[r['pattern'] for r in hits]))
    require(len(mappings)<=512,'expanded package limit')
    markers={};lines=['schema 3','enabled true','debug false',f'runtime_defaults {mode} {rt}']
    mask=lambda value:','.join(str(i) for i in range(8) if value&(1<<i))
    used=sorted({template for _,template in mappings})
    for name in used:
        rules=templates[name];require([r['order'] for r in rules]==list(range(len(rules))),'classifier order')
        controls=[r['pattern'] for r in rules if r['pattern'] in ('__DummyMain','__DoubleMain')]
        require(len(controls)<=1,'ambiguous control markers');marker={'__DummyMain':'dummy','__DoubleMain':'double'}.get(controls[0],'none') if controls else 'none';markers[name]=marker
        lines.extend((f'profile {name} {mask(124)}',f'runtime {name} -1 -1 preset {marker}'))
        for row in rules:
            require(row['match']=='contains' and row['category'] in (0,1,2) and isinstance(row['pattern'],str) and len(row['pattern'])<=64 and row['pattern'].isascii(),'classifier shape')
            if row['pattern'] in controls:continue
            category=row['category'];cls=('G','C1','C2')[category];selector='all' if category==0 else 'rank:1'
            lines.append(f'thread {name} {cls} contains {json.dumps(row["pattern"],ensure_ascii=True)} selector={selector} {100000-row["order"]} {mask((124,28,128)[category])}')
    needed=required_capabilities(mode,rt,markers.values());require(needed<=set(capabilities),'unsupported required capabilities: '+','.join(sorted(needed-set(capabilities))))
    for i,(name,profile) in enumerate(mappings):lines.append(f'package exact {name} {profile} {100000-i}')
    text='\n'.join(lines)+'\n';require(len(text.encode('ascii'))<=65536,'canonical size')
    return text.encode('ascii'),dict(required_capabilities=sorted(needed),markers=markers,expanded_packages=len(mappings),ambiguous_matches=ambiguities,installed_inventory=sorted(set(installed)),expansion_policy='Original first strstr wins; recompute on package install/uninstall/update',intentional_differences=['No arbitrary representative fallback for empty categories','Owned original scheduler/global restore and finite budget','Module service.sh side effects excluded'],publication='OWNER_CONFIRMATION_REQUIRED',online_feed_enabled=False)
