import requests
import json

re_conf = {
    'apikey': 'l1br3',
    'host': 'https://api.reveng.ai',
    'model': 'binnet-0.1'
}


def reveng_req(r: requests.request, end_point: str, data=None, ex_headers: dict = None, params=None):

    url = f"{re_conf['host']}/{end_point}"
    headers = {"Authorization": "bdee5ee1-17c9-4949-ae94-5a431597e085"}

    print(url,headers,data,params)
    return r(url, headers=headers, json=data)



res = reveng_req(r=requests.post,end_point="analyse",data={'file_name': 'false', 'sha_256_hash': '5079261fe383e6b7dc8473f837dcc2a7f5754bee6bd5b05ada89ca8c144060a1', 'model_name': 'binnet-0.1', 'binary_scope': 'PRIVATE'})

print(res.content)