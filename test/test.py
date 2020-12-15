# -*- coding: utf-8 -*-
from ufw_salt import manage_records
from ufw_salt import setup

__opts__ = {
    'test': False
}

res = setup({
    "enabled": True,
    "log_level": "full",
    "default_policy": {
        "incoming": "deny",
        "outgoing": "allow",
        "routed": "deny",
    }
})
print(res)

res = manage_records(records=[
    {
        "action": "allow",
        "protocol": "any",
        "dst_port": "3306",
        "dst": "127.0.0.1",
        "src_port": "2206",
        "src": "4.4.4.4",
        "direction": "in",
        "forward": False,
        "comment": "debug",
    },

])
print(res)
