from flask import Flask, request, Response, abort
from datetime import datetime, timedelta
import json
import requests
from requests_ntlm import HttpNtlmAuth


app = Flask(__name__)


class DataAccess:
    def __init__(self):
        self._entities = {"users": [], "groups": [], "documents": []}

    def get_entities(self, since, datatype, user, password):
        siteurl = "https://kunder.bouvet.no/Sesam"
        if not datatype in self._entities:
            abort(404)
        if since is None:
            return self.get_entitiesdata(siteurl, datatype, since, user, password)
        else:
            return [entity for entity in self.get_entitiesdata(siteurl, datatype, since) if entity["_updated"] > since]

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


@app.route('/<user>/<password>/<datatype>')
def get_entities(datatype, user, password):
    since = request.args.get('since')
    entities = data_access_layer.get_entities(since, datatype, user, password)
    return Response(json.dumps(entities), mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

