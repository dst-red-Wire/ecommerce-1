import argparse,json
p=argparse.ArgumentParser()
for n in ('sha','component','image','runner'):p.add_argument('--'+n,required=True)
a=p.parse_args();print(json.dumps({'git_sha':a.sha,'repository':a.image.split('@')[0],'component':a.component,'runner_digest':a.runner,'build_inputs':['source','Containerfile','tools.lock'],'output_digest':a.image,'tool_versions':{'syft':'1.33.0','trivy':'0.66.0','cosign':'3.1.3','oras':'1.3.3'}},sort_keys=True))
