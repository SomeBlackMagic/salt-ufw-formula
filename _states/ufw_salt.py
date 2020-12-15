# -*- coding: utf-8 -*-
import logging
# import salt.exceptions
import gettext
import salt.exceptions

import ufw.frontend
import ufw.common
import ufw.parser
import ufw.util
from ufw.common import UFWError



logger = logging.getLogger(__name__)
progName = ufw.common.programName
gettext.install(progName)


# Overwrite UFW class
class UFWRule(ufw.common.UFWRule):
    def set_comment(self, comment):
        '''Sets comment of the rule'''
        self.comment = ufw.util.hex_encode(comment)


class UFWFrontend(ufw.frontend.UFWFrontend):
    def set_default_policy(self, policy, direction):
        '''Sets default policy of firewall'''
        res = ""
        try:
            res = self.backend.set_default_policy(policy, direction)
            if self.backend.is_enabled():
                self.backend.stop_firewall()
                self.backend.start_firewall()
        except UFWError as e:  # pragma: no cover
            # print(e.value)
            raise salt.exceptions.SaltInvocationError(e.value)

        return res


ui = UFWFrontend(False)  # no dryrun -- do it live
backend = ui.backend


def setup(config):
    result = {"name": 'UFW'}

    if "reset" in config and config['reset'] == True:
        ui.reset(config['reset_force'])

    ui.set_enabled(config['enabled'])
    ui.set_loglevel(config['log_level'])
    if "default_policy" in config:
        ui.set_default_policy(config["default_policy"]["incoming"], "incoming")
        ui.set_default_policy(config["default_policy"]["outgoing"], "outgoing")
        ui.set_default_policy(config["default_policy"]["routed"], "routed")
    return {
        "name": 'UFW',
        "result": ui.get_status(True)
    }


def manage_records(records):
    managed = Server(records)

    # try:
    # managed.sanity_check()
    # except salt.exceptions.SaltInvocationError as err:
    #     return {
    #         "name": name,
    #         "changes": {},
    #         "result": False,
    #         "comment": "{0}".format(err)
    #     }

    diff = managed.diff()

    result = {"name": 'UFW', "changes": _changes(diff), "result": None}

    if len(diff) == 0:
        result["comment"] = "The state is up to date."
        result["changes"] = {}
        result["result"] = None if __opts__["test"] == True else True
        return result

    if __opts__["test"] == True:
        result[
            "comment"
        ] = "The state will be changed ({0} changes).".format(
            len(diff)
        )
        result["pchanges"] = result["changes"]
        return result

    managed.apply(diff)

    result["comment"] = "The state of was changed ({0} changes).".format(
        len(diff)
    )
    result["result"] = True

    return result


def _changes(diff):
    changes = {}
    actions = map(lambda op: "{0} {1}".format(op["action"], str(op["record"])), diff)
    if actions:
        changes['diff'] = "\n".join(actions)
    return changes


def validate_record(record):
    if "action" not in record:
        # print("'action' is required")
        raise salt.exceptions.SaltInvocationError("'name' is required")


def record_from_dict(record):
    record.setdefault("protocol", "tcp")
    record.setdefault("dst_port", "any")
    record.setdefault("dst", "0.0.0.0/0")
    record.setdefault("src_port", "any")
    record.setdefault("src", "0.0.0.0/0")
    record.setdefault("direction", "in")
    record.setdefault("forward", False)
    record.setdefault("comment", "")
    record.setdefault("dst_app", "")
    record.setdefault("src_app", "")

    rule = UFWRule(
        record["action"],
        record["protocol"],
        record["dst_port"],
        record["dst"],
        record["src_port"],
        record["src"],
        record["direction"],
        record["forward"],
        record["comment"],
    )
    rule.dapp = record["dst_app"]
    rule.sapp = record["src_app"]
    return rule


class Server(object):
    ACTION_ADD = "add"
    ACTION_REMOVE = "remove"
    ACTION_UPDATE = "update"

    SPECIAL_APPLY_ORDER = {ACTION_REMOVE: 0, ACTION_ADD: 1, ACTION_UPDATE: 2}

    REGULAR_APPLY_ORDER = {ACTION_ADD: 0, ACTION_UPDATE: 1, ACTION_REMOVE: 2}

    def __init__(self, records):
        self.records = records

    def _add_record(self, record):
        backend.set_rule(record)

    def _remove_record(self, record):
        record.remove = True
        backend.set_rule(record)

    def _update_record(self, record):
        print("Update not worked now. fixed")
        print(record)
        print("---------------------")

    def desired(self):
        for record in self.records:
            validate_record(record)
        return map(lambda record: record_from_dict(record.copy()), self.records)

    def diff(self):
        existing_tuples = {
            (record.protocol, record.action, record.src, record.sport, record.dst, record.dport, record.dapp,
             record.comment): record
            for record in backend.get_rules()
        }
        desired_tuples = {
            (record.protocol, record.action, record.src, record.sport, record.dst, record.dport, record.dapp,
             record.comment): record
            for record in self.desired()
        }
        desired_salt_managed = {
            # record.name: record.salt_managed for record in self.desired()
        }
        changes = []

        for key in set(desired_tuples).difference(existing_tuples):
            # if not desired_tuples[key].salt_managed:
            #     continue
            changes.append({"action": self.ACTION_ADD, "record": desired_tuples[key]})

        for key in set(existing_tuples).difference(desired_tuples):
            if key[1] in desired_salt_managed and desired_salt_managed[key[1]] == False:
                continue
            changes.append(
                {"action": self.ACTION_REMOVE, "record": existing_tuples[key]}
            )

        # for key in set(existing_tuples).intersection(desired_tuples):
        #     if (
        #         existing_tuples[key].pure() == desired_tuples[key]
        #         or not desired_tuples[key].salt_managed
        #     ):
        #         continue
        #     changes.append(
        #         {
        #             "action": self.ACTION_UPDATE,
        #             "record": Record(
        #                 existing_tuples[key].id,
        #                 desired_tuples[key].type,
        #                 desired_tuples[key].name,
        #                 desired_tuples[key].content,
        #                 priority=desired_tuples[key].priority,
        #                 proxied=desired_tuples[key].proxied,
        #                 ttl=desired_tuples[key].ttl,
        #                 salt_managed=True,
        #             ),
        #         }
        #     )

        return changes

    def apply(self, diff):
        for op in diff:
            if op["action"] == self.ACTION_ADD:
                self._add_record(op["record"])
            elif op["action"] == self.ACTION_REMOVE:
                self._remove_record(op["record"])
            elif op["action"] == self.ACTION_UPDATE:
                self._update_record(op["record"])
            else:
                raise Exception(
                    "Unknown action {0} for record {1}", op["action"], str(op["record"])
                )
