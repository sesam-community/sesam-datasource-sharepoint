from functools import wraps
from flask import Flask, request, Response, abort
from datetime import datetime, timedelta
import json
import requests
import os
from requests_ntlm import HttpNtlmAuth
import logging
import threading
import copy

app = Flask(__name__)
config = {}
config_since = None

logger = None

_lock_config = threading.Lock()


class DataAccess:
    def __init__(self):
        self._entities = {"users": [], "groups": [], "documents": [], "roleassignments": [], "roledefinitions": [],
                          "folders": [], "items": [], "files": [], "sites": []}
        self._odata = None
        self._siteurl = None

    def get_entities(self, since, datatype, user, password, odata):
        self._odata = odata
        if not datatype in self._entities:
            abort(404)

        with _lock_config:
            # Make a deep copy so we can serve multiple threads with potentially different config
            config_copy = copy.deepcopy(config)

        for s in config_copy:
            if "site-url" in config_copy[s]:
                if since is None:
                    for entity in self.get_entitiesdata(config_copy[s], datatype, since, user, password):
                        yield entity
                else:
                    for entity in self.get_entitiesdata(config_copy[s], datatype, since, user, password):
                        if entity["_updated"] > since:
                            yield entity

    def get_entitiesdata(self, siteconfig, datatype, since, user, password):
        # if datatype in self._entities:
        #	 if len(self._entities[datatype]) > 0 and self._entities[datatype][0]["_updated"] > "%sZ" % (datetime.now() - timedelta(hours=12)).isoformat():
        #		 return self._entities[datatype]

        try:
            now = datetime.now()
            start = since
            if since is None:
                start = (now - timedelta(days=5365)).isoformat()
            siteurl = siteconfig["site-url"]
            self._siteurl = siteurl
            listid = None
            if "list-guid" in siteconfig:
                listid = "getbyguid('%s')" % (siteconfig["list-guid"])
            elif "list-title" in siteconfig:
                listid = "getbytitle('%s')" % (siteconfig["list-title"])

            if self._odata:
                headers = {'accept': 'application/json; odata=%s' % self._odata}
            else:
                headers = {'accept': 'application/json'}
            entities = []
            if datatype == "sites" and not listid:
                logger.info("Reading sites: %s" % (siteurl))
                r = requests.get(siteurl + "_api/web", auth=HttpNtlmAuth(user, password), headers=headers)
                r.raise_for_status()
                e = json.loads(r.text)
                e.update({"site": siteurl})
                e.update(self.get_id(e))
                entities.append(e)

            if datatype == "users" and not listid:
                logger.info("Reading users from site: %s" % (siteurl))
                r = requests.get(siteurl + "_api/web/siteusers", auth=HttpNtlmAuth(user, password), headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)

                entities = self.get_result(obj)
                logger.debug("Got %s items from user list" % (str(len(entities))))
                for e in entities:
                    e.update({"site": siteurl})
                    e.update(self.get_id(e))

            if datatype == "groups" and not listid:
                logger.info("Reading groups from site: %s" % (siteurl))
                r = requests.get(siteurl + "_api/web/sitegroups", auth=HttpNtlmAuth(user, password), headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)
                entities = self.get_result(obj)
                logger.debug("Got %s items from group list" % (str(len(entities))))
                for e in entities:
                    e.update(self.get_id(e))
                    e.update({"site": siteurl})
                    logger.debug("Reading group users from: %s" % (e["_id"]))
                    r = requests.get(self.get_url(e["_id"]) + "/users", auth=HttpNtlmAuth(user, password),
                                     headers=headers)
                    if r.text:
                        usr = json.loads(r.text)
                        users = self.get_result(usr)
                        logger.debug("Got %s group users" % (str(len(users))))
                        if len(users) > 0:
                            e.update({"users": users})

            if datatype == "roleassignments" and not listid:
                logger.info("Reading roleassignments from site: %s" % (siteurl))
                r = requests.get(siteurl + "_api/web/roleassignments", auth=HttpNtlmAuth(user, password),
                                 headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)
                logger.debug("Got %s items from roleassignments list" % (str(len(self.get_result(obj)))))
                entities = self.get_result(obj)
                for e in entities:
                    e.update(self.get_id(e))
                    e.update({"site": siteurl})
                    logger.debug("Reading roleassignments member from: %s" % (e["_id"]))
                    r = requests.get(self.get_url(e["_id"]) + "/member", auth=HttpNtlmAuth(user, password),
                                     headers=headers)
                    if r.text:
                        logger.debug("Request result: %s" % (r.text))
                        usr = json.loads(r.text)
                        e.update({"member": self.get_member(usr)})
                    logger.debug("Reading roleassignments roledefinitionbindings from: %s" % (e["_id"]))
                    r = requests.get(self.get_url(e["_id"]) + "/roledefinitionbindings",
                                     auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        logger.debug("Request result: %s" % (r.text))
                        e.update({"roledefinitions": []})
                        usr = json.loads(r.text)
                        logger.debug("Got %s roledefinitionbindings" % (str(len(self.get_result(usr)))))
                        for r in self.get_result(usr):
                            e["roledefinitions"].append(self.get_id(r))

            if datatype == "roledefinitions" and not listid:
                logger.info("Reading roledefinitions from site: %s" % (siteurl))
                r = requests.get(siteurl + "_api/web/roledefinitions", auth=HttpNtlmAuth(user, password),
                                 headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)
                logger.debug("Got %s items from roledefinitions list" % (str(len(self.get_result(obj)))))
                entities = self.get_result(obj)
                for e in entities:
                    e.update(self.get_id(e))
                    e.update({"site": siteurl})

            if datatype == "folders" and not listid:
                logger.info("Reading folders from : %s" % (siteurl + "_api/web/folders"))
                r = requests.get(siteurl + "_api/web/folders", auth=HttpNtlmAuth(user, password), headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)
                logger.debug("Got %s items from folders list" % (str(len(self.get_result(obj)))))
                entities = self.get_result(obj)
                for e in entities:
                    e.update(self.get_id(e))
                    e.update({"site": siteurl})

            if datatype == "files" and not listid:
                logger.info("Reading folders from site: %s" % (siteurl + "_api/web/folders"))
                r = requests.get(siteurl + "_api/web/folders", auth=HttpNtlmAuth(user, password), headers=headers)
                r.raise_for_status()
                obj = json.loads(r.text)
                entities = []
                logger.debug("Got %s items from folders list" % (str(len(self.get_result(obj)))))
                folders = self.get_result(obj)
                for f in folders:
                    logger.debug("Reading folder files from: %s" % (self.get_fullid(f)))
                    r = requests.get(
                        self.get_url(self.get_fullid(f)) + "/files?$filter=TimeLastModified ge datetime'%s'" % (
                        start), auth=HttpNtlmAuth(user, password), headers=headers)
                    if r.text:
                        usr = json.loads(r.text)
                        for e in self.get_result(usr):
                            e.update({"site": siteurl})
                            e.update(self.get_id(e))
                            e.update({"folder": self.get_id(f)})
                            e.update({"_updated": str(e["TimeLastModified"])})
                        entities.extend(self.get_result(usr))

            if datatype == "items":
                if not listid:
                    logger.info("Ignoring lists in site: %s" % (siteurl))
                else:

                    logger.info("Reading documents from site: %s" % (siteurl))

                    logger.debug("Reading documents using: %s" % (listid))
                    r = requests.get(
                        siteurl + "_api/web/lists/%s/items?$filter=Modified ge datetime'%s'" % (listid, start),
                        auth=HttpNtlmAuth(user, password), headers=headers)
                    hura = requests.get(siteurl + "_api/web/lists/%s/HasUniqueRoleAssignments" % (listid),
                                        auth=HttpNtlmAuth(user, password), headers=headers)

                    hasuniqueroleassignments = self.is_uniqe(hura)
                    next = None
                    permissions = []
                    firstdocument = True
                    while True:
                        if r:
                            r.raise_for_status()
                            obj = json.loads(r.text)
                            logger.debug("Got %s items from document list" % (str(len(self.get_result(obj)))))
                            next = self.get_next(obj)
                            ent = self.get_result(obj)
                            for e in ent:
                                e.update(self.get_id(e))
                                e.update({"_updated": str(e["Modified"])})
                                e.update({"site": siteurl})
                                logger.debug(
                                    "Reading document file from: %s" % (e["_id"] + "/File"))
                                rf = requests.get(e["_id"] + "/File",
                                                  auth=HttpNtlmAuth(user, password), headers=headers)
                                if (rf.text and rf.ok) or "file" in e:
                                    usr = json.loads(rf.text)
                                    if not "odata.null" in usr and not (
                                                "d" in usr and "File" in usr["d"] and usr["d"]["File"] == None):
                                        e.update({"file": usr})
                                logger.debug(
                                    "Reading document folder from: %s" % (e["_id"] + "/Folder"))
                                rf = requests.get(e["_id"] + "/Folder",
                                                  auth=HttpNtlmAuth(user, password), headers=headers)
                                if (rf.text and rf.ok) or "folder" in e:
                                    usr = json.loads(rf.text)
                                    if not "odata.null" in usr and not (
                                                "d" in usr and "Folder" in usr["d"] and usr["d"]["Folder"] == None):
                                        e.update({"folder": usr})
                                if firstdocument or hasuniqueroleassignments:
                                    runcheck = True
                                    if firstdocument:
                                        firstdocument = False
                                    else:
                                        hura = requests.get(
                                            self.get_url(e["_id"]) + "/HasUniqueRoleAssignments",
                                            auth=HttpNtlmAuth(user, password), headers=headers)
                                        hasuniqueroleassignments = self.is_uniqe(hura)
                                        runcheck = hasuniqueroleassignments

                                    if runcheck:
                                        firstdocument = False
                                        logger.debug("Reading document RoleAssignments from: %s" % (
                                            self.get_url(e["_id"]) + "/RoleAssignments"))
                                        permissions = []
                                        rf = requests.get(self.get_url(e["_id"]) + "/RoleAssignments",
                                                          auth=HttpNtlmAuth(user, password), headers=headers)
                                        obj = json.loads(rf.text)
                                        logger.debug(
                                            "Got %s RoleAssignments from items list" % (str(len(self.get_result(obj)))))
                                        for r in self.get_result(obj):
                                            permissions.append(self.get_url(self.get_id(r)["_id"].replace(e["_id"],"Web")))

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
                    r = requests.get(
                        siteurl + "_api/web/lists/getbyguid('%s')/items?$filter=Modified ge datetime'%s'" % (
                        siteconfig["list-guid"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                    hura = requests.get(
                        siteurl + "_api/web/lists/getbyguid('%s')/HasUniqueRoleAssignments" % (siteconfig["list-guid"]),
                        auth=HttpNtlmAuth(user, password), headers=headers)
                elif "list-title" in siteconfig:
                    logger.debug("Reading documents using title: %s" % (siteconfig["list-title"]))
                    r = requests.get(
                        siteurl + "_api/web/lists/getbytitle('%s')/items?$filter=Modified ge datetime'%s'" % (
                        siteconfig["list-title"], start), auth=HttpNtlmAuth(user, password), headers=headers)
                    hura = requests.get(siteurl + "_api/web/lists/getbytitle('%s')/HasUniqueRoleAssignments" % (
                    siteconfig["list-title"]), auth=HttpNtlmAuth(user, password), headers=headers)

                hasuniqueroleassignments = True
                if hura:
                    huraobj = json.loads(hura.text)
                    hasuniqueroleassignments = self.get_result(huraobj)
                    logger.debug("Documentlibrary has unique role assignments: %r" % hasuniqueroleassignments)
                next = None
                permissions = []
                firstdocument = True
                while True:
                    if r:
                        r.raise_for_status()
                        obj = json.loads(r.text)
                        logger.debug("Got %s items from document list" % (str(len(self.get_result(obj)))))
                        next = self.get_next(obj)

                        if "value" in obj:
                            ent = self.get_result(obj)
                            for e in ent:
                                e.update(self.get_id(e))
                                e.update({"_updated": str(e["Modified"])})
                                if firstdocument | hasuniqueroleassignments:
                                    firstdocument = False
                                    logger.debug("Reading document RoleAssignments from: %s" % (
                                    e["RoleAssignments"]["__deferred"]["uri"]))
                                    p = requests.get(e["RoleAssignments"]["__deferred"]["uri"],
                                                     auth=HttpNtlmAuth(user, password), headers=headers)
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
        except BaseException as e:
            logger.exception("Crashed while trying to read data from sharepoint")
            raise e

        return self._entities[datatype]

    def get_fullid(self, f):
        if self._odata and self._odata == "verbose":
            return f["__metadata"]["id"]
        else:
            return f["odata.id"]

    def get_url(self, id):
        if id.startswith(self._siteurl):
            return id
        url = self._siteurl + "_api/" + id
        logger.debug("Using %s as URL" % (url))
        return url

    def get_member(self, usr):
        if "d" in usr:
            return self.get_url(usr["d"]["__metadata"]["id"])
        if "odata.editLink" in usr:
            return self.get_url(usr["odata.editLink"])
        return {}

    def is_uniqe(self, hura):
        hasuniqueroleassignments = False
        if hura.text:
            logger.debug("HasUniqueRoleAssignments returns: %s" % (hura.text))
            huraobj = json.loads(hura.text)
            if self._odata and self._odata == "verbose" and "d" in huraobj:
                hasuniqueroleassignments = huraobj["d"]["HasUniqueRoleAssignments"]
            else:
                hasuniqueroleassignments = huraobj["value"]
            logger.debug("Documentlibrary has unique role assignments: %r" % hasuniqueroleassignments)
        return hasuniqueroleassignments

    def get_result(self, obj):
        if self._odata and self._odata == "verbose" and "d" in obj:
            return obj["d"]["results"]
        elif "value" in obj:
            return obj["value"]
        else:
            return {}

    def get_id(self, e):
        if self._odata and self._odata == "verbose":
            return {"_id": self.get_url(e["__metadata"]["id"])}
        else:
            return {"_id": self.get_url(e["odata.id"])}

    def get_next(self, e):
        if self._odata and self._odata == "verbose" and "__next" in e["d"]:
            return e["d"]["__next"]
        elif "odata.nextLink" in e:
            return e["odata.nextLink"]
        logger.debug("No more pages...")
        return None


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

    with _lock_config:
        # To keep locking minimal, operate on copies
        config_copy = copy.deepcopy(config)
        _config_since = copy.deepcopy(config_since)

    parameter = "?history=false"
    if _config_since:
        parameter = parameter + "&since=%s" % (str(_config_since))

    logger.info("Reading config dataset from %s" % (config_url + parameter))
    r = requests.get(config_url + parameter)
    r.raise_for_status()
    logger.debug("Reading config from %s: %s" % (config_url + parameter, r.text))
    change = json.loads(r.text)
    for changed_item in change:
        changed_item_id = changed_item["_id"]
        if changed_item["_deleted"]:
            logger.debug("Deletes _id %s" % (changed_item["_id"]))
            if changed_item_id in config_copy:
                del config_copy[changed_item_id]
        else:
            logger.debug("Updates _id %s with: %s" % (changed_item["_id"], changed_item))
            config_copy[changed_item_id] = changed_item
        changed_item_updated = changed_item["_updated"]

        if _config_since is None or changed_item_updated > _config_since:
            _config_since = changed_item_updated

    with _lock_config:
        config = config_copy
        config_since = _config_since


@app.route('/<datatype>')
@requires_auth
def get_entities(datatype):
    logger.info("Get %s using request: %s" % (datatype, request.url))
    since = request.args.get('since')
    conf = get_var("config_dataset")
    odata = get_var("odata")
    auth = request.authorization

    def generate(entities):
        # Wrapper generator to produce streaming json
        i = 0
        yield "["
        for index, entity in enumerate(entities):
            if index > 0:
                yield ","

            i = index
            yield json.dumps(entity)
        logger.info("Produced '%s entitites, closing stream" % i)
        yield "]"

    if conf:
        try:
            read_config(conf)
            logger.info("Configuration loaded")
        except BaseException as e:
            logger.exception("Failed to read config!")
            return Response(status=500, response="An error occured during reading config")

    logger.info("Reading entities...")
    try:
        return Response(generate(data_access_layer.get_entities(since, datatype, auth.username, auth.password, odata)),
                        mimetype='application/json')
    except BaseException as e:
        logger.exception("Failed to read entities!")
        return Response(status=500, response="An error occured during generation of entities")


def get_var(var):
    envvar = None
    if var.upper() in os.environ:
        envvar = os.environ[var.upper()]
    else:
        envvar = request.args.get(var)
    logger.info("Setting %s = %s" % (var, envvar))
    return envvar


if __name__ == '__main__':
    # Set up logging
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logger = logging.getLogger('sharepoint-microservice')

    # Log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(stdout_handler)

    logger.setLevel(logging.DEBUG)

    app.run(threaded=True, debug=True, host='0.0.0.0')
