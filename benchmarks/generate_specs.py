"""Derive a deliberately limited, non-official spec from pinned deployed source."""
import copy
import sys
from pathlib import Path
from . import core

def generate():
    deps=core.ROOT/'local/validation-deps'
    if deps.is_dir(): sys.path.insert(0,str(deps))
    source=core.ROOT/'sources/juice-shop-20.0.0'
    server=(source/'server.ts').read_text()
    version=core.load(source/'package.json')['version']
    core.require(version=='20.0.0','Source version drift')
    original=source/'swagger.yml'
    dest=core.ROOT/'specs/original/juice-shop-20.0.0-b2b.yml'
    dest.parent.mkdir(parents=True,exist_ok=True)
    if dest.exists(): core.require(dest.read_bytes()==original.read_bytes(),'Original specification changed')
    else: dest.write_bytes(original.read_bytes())
    official=core.load(original)
    for label,origin in [('host','http://127.0.0.1:18001'),('docker','http://host.docker.internal:18001')]:
        prepared=core.prepare_origin(official,origin)
        path=core.ROOT/f'specs/prepared/juice-shop-20.0.0-b2b-{label}.json'
        core.save(path,prepared)
        core.save(core.ROOT/f'specs/validation/b2b-{label}-provenance.json',{
            'original':str(dest.relative_to(core.ROOT)),'original_sha256':core.sha(dest),
            'prepared':str(path.relative_to(core.ROOT)),'prepared_sha256':core.sha(path),
            'transformations':['Parse YAML to JSON','Resolve relative server /b2b/v2 against verified origin'],
            'schemas_and_security_preserved':True,'product_version':version,'api_info_version':official['info']['version']})
    recipes=[
        ('/rest/admin/application-version','getApplicationVersion','routes/appVersion.ts',[],
         {'type':'object','properties':{'version':{'type':'string'}},'required':['version']}),
        ('/rest/languages','getLanguages','routes/languages.ts',[],
         {'type':'array','items':{'type':'object','additionalProperties':True}}),
        ('/rest/products/search','searchProducts','routes/search.ts',[
            {'name':'q','in':'query','required':False,'schema':{'type':'string','maxLength':200},'example':'apple',
             'description':'Optional product-search string; benign validation uses apple. Source truncates at 200 characters.'}],
         {'type':'object','additionalProperties':True}),
        ('/rest/products/{id}/reviews','getProductReviews','routes/showProductReviews.ts',[
            {'name':'id','in':'path','required':True,'schema':{'type':'string','maxLength':40},'example':'1',
             'description':'Source route accepts a string and conditionally coerces it. Only benign numeric ID 1 was live-checked.'}],
         {'type':'object','additionalProperties':True}),
        ('/rest/country-mapping','getCountryMapping','routes/countryMapping.ts',[],None)
    ]
    spec={'openapi':'3.0.3','info':{'title':'NON-OFFICIAL Juice Shop 20.0.0 read-only source-derived subset','version':'20.0.0-phase4.1',
        'description':'Non-official and incomplete. Source routes and benign observations, not an official full API specification. Response fields not modeled are intentionally unconstrained.'},
        'x-penagent-target-version':version,'x-specification-origin':'derived-non-official',
        'servers':[{'url':'http://127.0.0.1:18001'}],'security':[],'paths':{}}
    for path,oid,handler,parameters,response_schema in recipes:
        express=path.replace('{id}',':id')
        declaration="app.get('"+express+"'"
        core.require(declaration in server,'Route absent from pinned source: '+declaration)
        core.require((source/handler).is_file(),'Handler source missing')
        responses={'200':{'description':'Source-declared successful response; live verification is recorded separately'}}
        if response_schema: responses['200']['content']={'application/json':{'schema':response_schema}}
        if path=='/rest/country-mapping': responses['500']={'description':'Source returns 500 when CTF country mapping is absent'}
        spec['paths'][path]={'get':{'operationId':oid,'security':[],'parameters':parameters,'responses':responses,
            'x-schema-assurance':'Parameters directly inspected in source; response schema partial/open, not complete',
            'x-penagent-evidence':[{'path':'sources/juice-shop-20.0.0/server.ts','sha256':core.sha(source/'server.ts'),
                'route_declaration':declaration},{'path':'sources/juice-shop-20.0.0/'+handler,'sha256':core.sha(source/handler)}]}}
    output=core.ROOT/'specs/original/juice-shop-20.0.0-readonly-derived.json'
    core.save(output,spec)
    for label,origin in [('host','http://127.0.0.1:18001'),('docker','http://host.docker.internal:18001')]:
        prepared=core.prepare_origin(spec,origin)
        core.save(core.ROOT/f'specs/prepared/juice-shop-20.0.0-readonly-{label}.json',prepared)
    core.save(core.ROOT/'specs/validation/derived-provenance.json',{
        'generator':'python -m benchmarks.generate_specs','official':False,'completeness':'Deliberate five-operation subset; response schemas incomplete',
        'original_sha256':core.sha(output),'target_version':version,'source_image_digest':
        'bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f',
        'unverified_schema_parts':['Response fields beyond version, envelope/array shape','Authenticated behavior','Error responses other than documented country-mapping configuration failure'],
        'not_authorized':['Account creation','Order placement','Mutations','Active scanning','Automated crawling']})
    for name in ['juice-shop-20.0.0-b2b-host.json','juice-shop-20.0.0-readonly-host.json']:
        path=core.ROOT/'specs/prepared'/name
        report=core.inspect_spec(core.load(path),full=True)
        report['sha256']=core.sha(path)
        core.save(core.ROOT/'specs/validation'/(name+'.validation.json'),report)
    print('Generated official B2B addressing copies and labeled non-official five-operation subset; full OAS validation passed')

if __name__=='__main__': generate()
