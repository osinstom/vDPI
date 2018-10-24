from dppclient.common.base import BaseClient
import warlock
import json

BASE_PATH = 'p4/modules'

SCHEMA = {
    "additionalProperties": {
        "type": "string"
    },
    "name": "module",
    "properties": {
        "project_id": {
            "type": "string"
        },
        "network_id": {
            "type": "string"
        },
        "name": {
            "type": "string"
        },
        "description": {
            "type": "string"
        },
        "program": {
            "type": "string"
        }
    }
}

NEUTRON_URL = 'http://%s:9696/v2.0'


class Modules(BaseClient):

    def __init__(self, auth, host_ip):
        super(Modules, self).__init__(auth, NEUTRON_URL % host_ip)

    def model(self):
        model = warlock.model_factory(SCHEMA)
        return model()

    def list(self):
        return self.send_get(BASE_PATH).json()

    def get(self, **kwargs):
        path = "%s/%s" % (BASE_PATH, kwargs['id'])
        return self.send_get(BASE_PATH).json()

    def create(self, **kwargs):
        module = self.model()

        for (key, value) in kwargs.items():
            try:
                setattr(module, key, value)
            except warlock.InvalidOperation as e:
                raise TypeError(e)

        obj = dict(module=module)
        data = json.dumps(obj)

        print data

        resp = self.send_post(BASE_PATH, data=data)

        return resp.status_code, resp.json()

    def delete(self, **kwargs):
        path = "%s/%s" % (BASE_PATH, kwargs['id'])
        return self.send_delete(path).status_code

    def attach(self, **kwargs):
        path = "%s/%s/attach" % (BASE_PATH, kwargs['id'])
        data = {
            "chain_with": [kwargs['chain_with']],
            "type": "outgoing",
            "flow_filter": {
                "protocol": kwargs['protocol'],
                "destination_ip_prefix": kwargs['dst_ip'],
                "source_ip_prefix": kwargs['src_ip']
            }
        }
        return self.send_put(path, data=json.dumps(data))

    def detach(self, **kwargs):
        path = "%s/%s/detach" % (BASE_PATH, kwargs['id'])
        data = {}
        return self.send_put(path, data=data)

    def configure(self, **kwargs):
        path = "%s/%s/configure" % (BASE_PATH, kwargs['id'])
        data = {
            "configuration": {
                "flow_rules": [
                    {
                        "table_id": kwargs['table_name'],
                        "entry": {
                            "type": "runtime",
                            "match_keys": kwargs['match_keys'],
                            "action_name": kwargs['action_name'],
                            "action_params": kwargs['action_data'],
                            "priority": kwargs['priority']
                        }
                    }
                ]
            }
        }
        return self.send_put(path, data=json.dumps(data))

    def unconfigure(self, **kwargs):
        path = "%s/%s/configure" % (BASE_PATH, kwargs['id'])
        data = {
            "configuration": {
                "flow_rules": [
                    {
                        "table_id": kwargs['table_name'],
                        "entry": {
                            "type": "runtime",
                            "match_keys": kwargs['match_keys'],
                            "action_name": kwargs['action_name'],
                            "action_params": kwargs['action_data'],
                            "priority": kwargs['priority']
                        }
                    }
                ]
            }
        }
        return self.send_put(path, data=data)
