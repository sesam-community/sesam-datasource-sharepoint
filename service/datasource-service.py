from functools import wraps
from flask import Flask, request, Response, abort
from datetime import datetime, timedelta
import json
import requests
import operator
import os
from requests_ntlm import HttpNtlmAuth


app = Flask(__name__)
config = {}
config_since = 0


class DataAccess:
    def __init__(self):
        self._entities = {"users": [], "groups": [], "documents": []}

    def get_entities(self, since, datatype, user, password):
        if not datatype in self._entities:
            abort(404)
        result = []
        for s in config:
            if "site-url" in s:
                siteurl = s["site-url"]
                if since is None:
                    result.extend( self.get_entitiesdata(siteurl, datatype, since, user, password))
                else:
                    result.extend( [entity for entity in self.get_entitiesdata(siteurl, datatype, since) if entity["_updated"] > since])
        return result

    def get_entitiesdata(self, siteurl, datatype, since, user, password):
        if datatype in self._entities:
            if len(self._entities[datatype]) > 0 and self._entities[datatype][0]["_updated"] > "%sZ" % (datetime.now() - timedelta(hours=12)).isoformat():
                return self._entities[datatype]
        now = datetime.now()
        start = since
        if since is None:
            start = (now - timedelta(days=5365)).isoformat()

        headers = {'accept': 'application/json;odata=verbose'}
        entities = []
        if datatype == "users":
            r = requests.get(siteurl + "/_api/web/siteusers", auth=HttpNtlmAuth(user, password), headers=headers)
            obj = json.loads(r.text)

            if "d" in obj:
                entities = obj["d"]["results"]
                for e in entities:
                    e.update({"_id": str(e["Id"])})
                    e.update({"_updated": now.isoformat()})

        if datatype == "groups":
            r = requests.get(siteurl + "/_api/web/sitegroups", auth=HttpNtlmAuth(user, password), headers=headers)
            obj = json.loads(r.text)
            if "d" in obj:
                entities = obj["d"]["results"]
                for e in entities:
                    e.update({"_id": str(e["Id"])})
                    e.update({"_updated": now.isoformat()})
                    r = requests.get(e["Users"]["__deferred"]["uri"], auth=HttpNtlmAuth(user, password), headers=headers)
                    usr = json.loads(r.text)
                    if "d" in usr:
                        e.update({"users-metadata": usr["d"]["results"]})

        if datatype == "documents":
            r = requests.get(siteurl + "/_api/web/lists/getbytitle('Documents')/items", auth=HttpNtlmAuth(user, password), headers=headers)
            obj = json.loads(r.text)
            if "d" in obj:
                entities = obj["d"]["results"]
                for e in entities:
                    e.update({"_id": str(e["Id"])})
                    e.update({"_updated": now.isoformat()})
                    r = requests.get(e["File"]["__deferred"]["uri"], auth=HttpNtlmAuth(user, password), headers=headers)
                    usr = json.loads(r.text)
                    if "d" in usr:
                        e.update({"file-metadata": usr["d"]})

        self._entities[datatype] = entities
        return self._entities[datatype]

data_access_layer = DataAccess()

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def read_config(config_url):
    global config_since
    global config
    r = requests.get(config_url + "?since=%s&history=false" % (str(config_since-1)))
    change = json.loads(r.text)
    for changed_item in change:
        changed_item_id = changed_item["_id"]
        if changed_item["_deleted"]:
            if changed_item_id in config:
                del config[changed_item_id]
        else:
            config[changed_item_id] = changed_item
        changed_item_updated = changed_item["_updated"]
        if config_since is None or changed_item_updated > config_since:
            config_since = changed_item_updated

@app.route('/<datatype>')
@requires_auth
def get_entities(datatype):
    since = request.args.get('since')
    conf = None
    if 'CONFIG_DATASET' in os.environ:
        conf = os.environ['CONFIG_DATASET']
    if not conf:
        conf = request.args.get('config-dataset')
    if conf:
        read_config(conf)
    auth = request.authorization
    entities = data_access_layer.get_entities(since, datatype, auth.username, auth.password)
    return Response(json.dumps(entities), mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

