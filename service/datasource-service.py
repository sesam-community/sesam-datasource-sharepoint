from functools import wraps
from flask import Flask, request, Response, abort
from datetime import datetime, timedelta
import json
import requests
import os
from requests_ntlm import HttpNtlmAuth
import logging


app = Flask(__name__)
config = {}
config_since = None

logger = None


class DataAccess:
    def __init__(self):
        self._entities = {"users": [], "groups": [], "documents": [], "roleassignments": [], "roledefinitions": [], "folders": [], "items": [], "files": []}

    def get_entities(self, since, datatype, user, password):
        if not datatype in self._entities:
            abort(404)
        result = []
        for s in config:
            if  "site-url" in config[s]:
                if since is None:
                    result.extend( self.get_entitiesdata(config[s], datatype, since, user, password))
                else:
                    result.extend( [entity for entity in self.get_entitiesdata(config[s], datatype, since, user, password) if entity["_updated"] > since])
        return result

    def get_entitiesdata(self, siteconfig, datatype, since, user, password):
        #if datatype in self._entities:
        #    if len(self._entities[datatype]) > 0 and self._entities[datatype][0]["_updated"] > "%sZ" % (datetime.now() - timedelta(hours=12)).isoformat():
        #        return self._entities[datatype]
        now = datetime.now()
        start = since
        if since is None:
            start = (now - timedelta(days=5365)).isoformat()
        siteurl = siteconfig["site-url"]
        headers = {'accept': 'application/json; odata=minimalmetadata'}
        entities = []
        if datatype == "users":
            logger.info("Reading users from site: %s" % (siteurl))
            r = requests.get(siteurl + "/_api/web/siteusers", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)

            if "value" in obj:
                logger.debug("Got %s items from user list" % (str(len(obj["value"]))))
                entities = obj["value"]
                for e in entities:
                    e.update({"_id": e["odata.editLink"]})

        if datatype == "groups":
            logger.info("Reading groups from site: %s" % (siteurl))
            r = requests.get(siteurl + "/_api/web/sitegroups", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)
            if "value" in obj:
                logger.debug("Got %s items from group list" % (str(len(obj["value"]))))
                entities = obj["value"]
                for e in entities:
                    e.update({"_id": e["odata.editLink"]})
                    logger.debug("Reading group users from: %s" % (e["odata.id"]))
                    r = requests.get(e["odata.id"] + "/users", auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        usr = json.loads(r.text)
                        if "value" in usr:
                            logger.debug("Got %s group users" % (str(len(usr["value"]))))
                            e.update({"users": usr["value"]})

        if datatype == "roleassignments":
            logger.info("Reading roleassignments from site: %s" % (siteurl))
            r = requests.get(siteurl + "/_api/web/roleassignments", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)
            if "value" in obj:
                logger.debug("Got %s items from roleassignments list" % (str(len(obj["value"]))))
                entities = obj["value"]
                for e in entities:
                    e.update({"_id": e["odata.editLink"]})
                    logger.debug("Reading roleassignments member from: %s" % (e["odata.id"]))
                    r = requests.get(e["odata.id"] + "/member", auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        usr = json.loads(r.text)
                        if "odata.editLink" in usr:
                            e.update({"member": usr["odata.editLink"]})
                    logger.debug("Reading roleassignments roledefinitionbindings from: %s" % (e["odata.id"]))
                    r = requests.get(e["odata.id"] + "/roledefinitionbindings", auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        e.update({"roledefinitions": []})
                        usr = json.loads(r.text)
                        if "value" in usr:
                            logger.debug("Got %s roledefinitionbindings" % (str(len(usr["value"]))))
                            for r in usr["value"]:
                                e["roledefinitions"].append(r["odata.editLink"])

        if datatype == "roledefinitions":
            logger.info("Reading roledefinitions from site: %s" % (siteurl))
            r = requests.get(siteurl + "/_api/web/roledefinitions", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)
            if "value" in obj:
                logger.debug("Got %s items from roledefinitions list" % (str(len(obj["value"]))))
                entities = obj["value"]
                for e in entities:
                    e.update({"_id": e["odata.editLink"]})

        if datatype == "folders":
            logger.info("Reading folders from site: %s" % (siteurl))
            r = requests.get(siteurl + "_api/web/folders", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)
            if "value" in obj:
                logger.debug("Got %s items from folders list" % (str(len(obj["value"]))))
                entities = obj["value"]
                for e in entities:
                    e.update({"_id": e["odata.editLink"]})

        if datatype == "files":
            logger.info("Reading folders from site: %s" % (siteurl))
            r = requests.get(siteurl + "_api/web/folders", auth=HttpNtlmAuth(user, password), headers=headers)
            r.raise_for_status()
            obj = json.loads(r.text)
            entities = []
            if "value" in obj:
                logger.debug("Got %s items from folders list" % (str(len(obj["value"]))))
                folders = obj["value"]
                for f in folders:
                    logger.debug("Reading folder files from: %s" % (f["odata.id"]))
                    r = requests.get(f["odata.id"] + "/files?$filter=TimeLastModified ge datetime'%s'" %(start), auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        usr = json.loads(r.text)
                        if "value" in usr and len(usr["value"])>0:
                            for e in usr["value"]:
                                e.update({"_id": e["odata.editLink"]})
                                e.update({"folder": f["odata.editLink"]})
                                e.update({"_updated": str(e["TimeLastModified"])})
                            entities.extend(usr["value"])


        if datatype == "items":
            logger.info("Reading documents from site: %s" % (siteurl))

            hura = None
            r = None
            if "list-guid" in siteconfig:
                logger.debug("Reading documents using GUID: %s" % (siteconfig["list-guid"]))
                r = requests.get(siteurl + "_api/web/lists/getbyguid('%s')/items?$filter=Modified ge datetime'%s'" %(siteconfig["list-guid"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                hura = requests.get(siteurl + "_api/web/lists/getbyguid('%s')/HasUniqueRoleAssignments" %(siteconfig["list-guid"]), auth=HttpNtlmAuth(user, password), headers=headers)
            elif "list-title" in siteconfig:
                logger.debug("Reading documents using title: %s" % (siteconfig["list-title"]))
                r = requests.get(siteurl + "_api/web/lists/getbytitle('%s')/items?$filter=Modified ge datetime'%s'" %(siteconfig["list-title"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                hura = requests.get(siteurl + "_api/web/lists/getbytitle('%s')/HasUniqueRoleAssignments" %(siteconfig["list-title"]), auth=HttpNtlmAuth(user, password), headers=headers)

            hasuniqueroleassignments = False
            if hura.text:
                logger.debug("HasUniqueRoleAssignments returns: %s" %(hura.text))
                huraobj = json.loads(hura.text)
                hasuniqueroleassignments = huraobj["value"]
                logger.debug("Documentlibrary has unique role assignments: %r" % hasuniqueroleassignments)
            next = None
            permissions = []
            firstdocument = True
            while True:
                if r:
                    r.raise_for_status()
                    obj = json.loads(r.text)
                    logger.debug("Got %s items from document list" % (str(len(obj["value"]))))
                    if "odata.nextLink" in obj:
                        next = obj["odata.nextLink"]
                        logger.debug("There are still more pages..." )
                    if "value" in obj:
                        ent = obj["value"]
                        for e in ent:
                            e.update({"_id": e["odata.editLink"]})
                            e.update({"_updated": str(e["Modified"])})
                            # logger.debug("Reading document file from: %s" % (siteurl + "_api/" + e["odata.id"] + "/File"))
                            # rf = requests.get(siteurl + "_api/" + e["odata.id"] + "/File", auth=HttpNtlmAuth(user, password), headers=headers)
                            # if (rf.text and rf.ok) or "file" in e:
                            #     usr = json.loads(rf.text)
                            #     if not "odata.null" in usr:
                            #         e.update({"file": usr})
                            if  firstdocument or hasuniqueroleassignments:
                                firstdocument = False
                                logger.debug("Reading document RoleAssignments from: %s" % (
                                siteurl + "_api/" + e["odata.id"] + "/RoleAssignments"))
                                permissions = []
                                rf = requests.get(siteurl + "_api/" + e["odata.id"] + "/RoleAssignments",
                                                  auth=HttpNtlmAuth(user, password), headers=headers)
                                if (rf.text and rf.ok) or "file" in e:
                                    obj = json.loads(rf.text)
                                    if "value" in obj:
                                        logger.debug(
                                            "Got %s RoleAssignments from items list" % (str(len(obj["value"]))))
                                        for r in obj["value"]:
                                            permissions.append(r["odata.editLink"])

                            e.update({"file-permissions": permissions})
                        entities.extend(ent)

                if next:
                    r = requests.get(
                        next, auth=HttpNtlmAuth(user, password), headers=headers)
                    next = None
                else:
                    break


        if datatype == "documents":
            logger.info("Reading documents from site: %s" % (siteurl))

            hura = None
            r = None
            if "list-guid" in siteconfig:
                logger.debug("Reading documents using GUID: %s" % (siteconfig["list-guid"]))
                r = requests.get(siteurl + "_api/web/lists/getbyguid('%s')/items?$filter=Modified ge datetime'%s'" %(siteconfig["list-guid"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                hura = requests.get(siteurl + "_api/web/lists/getbyguid('%s')/HasUniqueRoleAssignments" %(siteconfig["list-guid"]), auth=HttpNtlmAuth(user, password), headers=headers)
            elif "list-title" in siteconfig:
                logger.debug("Reading documents using title: %s" % (siteconfig["list-title"]))
                r = requests.get(siteurl + "_api/web/lists/getbytitle('%s')/items?$filter=Modified ge datetime'%s'" %(siteconfig["list-title"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                hura = requests.get(siteurl + "_api/web/lists/getbytitle('%s')/HasUniqueRoleAssignments" %(siteconfig["list-title"]), auth=HttpNtlmAuth(user, password), headers=headers)

            hasuniqueroleassignments = True
            if hura:
                huraobj = json.loads(hura.text)
                hasuniqueroleassignments = huraobj["value"]
                logger.debug("Documentlibrary has unique role assignments: %r" % hasuniqueroleassignments)
            next = None
            permissions = []
            firstdocument = True
            while True:
                if r:
                    r.raise_for_status()
                    obj = json.loads(r.text)
                    logger.debug("Got %s items from document list" % (str(len(obj["value"]))))
                    if "odata.nextLink" in obj:
                        next = obj["odata.nextLink"]
                        logger.debug("There are still more pages..." )
                    if "value" in obj:
                        ent = obj["value"]
                        for e in ent:
                            e.update({"_id": e["odata.editLink"]})
                            e.update({"_updated": str(e["Modified"])})
                            if firstdocument | hasuniqueroleassignments:
                                firstdocument = False
                                logger.debug("Reading document RoleAssignments from: %s" % (e["RoleAssignments"]["__deferred"]["uri"]))
                                p = requests.get(e["RoleAssignments"]["__deferred"]["uri"], auth=HttpNtlmAuth(user, password), headers=headers)
                                ra = json.loads(p.text)
                                if "d" in ra:
                                    permissions = ra["d"]
                                    for ro in permissions["results"]:
                                        logger.debug("Reading document RoleDefinitionBindings from: %s" % (
                                            ro["RoleDefinitionBindings"]["__deferred"]["uri"]))
                                        role = requests.get(ro["RoleDefinitionBindings"]["__deferred"]["uri"],
                                                         auth=HttpNtlmAuth(user, password), headers=headers)
                                        roo = json.loads(role.text)
                                        if "d" in roo:
                                            ro.update({"RoleDefinitionBindings-matadata": roo})
                                        logger.debug("Reading document Member from: %s" % (
                                            ro["Member"]["__deferred"]["uri"]))
                                        member = requests.get(ro["Member"]["__deferred"]["uri"],
                                                            auth=HttpNtlmAuth(user, password), headers=headers)
                                        mem = json.loads(member.text)
                                        if "d" in mem:
                                            ro.update({"Member-matadata": mem})
                            e.update({"file-permissions": permissions})
                        entities.extend(ent)

                if next:
                    r = requests.get(
                        next, auth=HttpNtlmAuth(user, password), headers=headers)
                    next = None
                else:
                    break
        logger.debug("Adding %s items to result" % (str(len(entities))))
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
    parameter = "?history=false"
    if config_since:
        parameter = parameter + "&since=%s" %(str(config_since))

    logger.info("Reading config dataset from %s" % (config_url + parameter))
    r = requests.get(config_url + parameter)
    r.raise_for_status()
    logger.debug("Reading config from %s: %s" % (config_url + parameter, r.text))
    change = json.loads(r.text)
    for changed_item in change:
        changed_item_id = changed_item["_id"]
        if changed_item["_deleted"]:
            logger.debug("Deletes _id %s" % (changed_item["_id"]))
            if changed_item_id in config:
                del config[changed_item_id]
        else:
            logger.debug("Updates _id %s with: %s" % (changed_item["_id"], changed_item))
            config[changed_item_id] = changed_item
        changed_item_updated = changed_item["_updated"]
        if config_since is None or changed_item_updated > config_since:
            config_since = changed_item_updated


@app.route('/<datatype>')
@requires_auth
def get_entities(datatype):
    logger.info("Get %s using request: %s" % (datatype, request.url))
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
    # Set up logging
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logger = logging.getLogger('sharepoint-microservice')

    # Log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(stdout_handler)

    logger.setLevel(logging.DEBUG)

    app.run(debug=True, host='0.0.0.0')

