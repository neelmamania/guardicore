import ta_guardicore_add_on_for_splunk_declare

import os
import sys
import time
import datetime
import json

import modinput_wrapper.base_modinput
from solnlib.packages.splunklib import modularinput as smi



import input_module_guardicore_centratest_1593025603_198 as input_module

bin_dir = os.path.basename(__file__)

'''
    Do not edit this file!!!
    This file is generated by Add-on builder automatically.
    Add your modular input logic to file input_module_guardicore_centra.py
'''
class ModInputguardicore_centra(modinput_wrapper.base_modinput.BaseModInput):

    def __init__(self):
        if 'use_single_instance_mode' in dir(input_module):
            use_single_instance = input_module.use_single_instance_mode()
        else:
            use_single_instance = False
        super(ModInputguardicore_centra, self).__init__("ta_guardicore_add_on_for_splunk", "guardicore_centra", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputguardicore_centra, self).get_scheme()
        scheme.title = ("Guardicore Centra")
        scheme.description = ("Go to the add-on\'s configuration UI and configure modular inputs under the Inputs menu.")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(smi.Argument("name", title="Name",
                                         description="",
                                         required_on_create=True))

        """
        For customized inputs, hard code the arguments here to hide argument detail from users.
        For other input types, arguments should be get from input_module. Defining new input types could be easier.
        """
        scheme.add_argument(smi.Argument("api_username", title="API Username",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("api_password", title="API Password",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("centra_management_server", title="Centra Management Server",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("port", title="Port",
                                         description="",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("connection_aggregation_time", title="Connection Aggregation Time ",
                                         description="Aggregation time in the management server (minutes)",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("collect_allowed_connections", title="Collect Allowed Connections",
                                         description="By default only Alert/Block connections are collected",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("collect_data", title="Collect Data",
                                         description="",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("request_timeout", title="Request Timeout",
                                         description="",
                                         required_on_create=True,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "TA-guardicore-add-on-for-splunk"

    def validate_input(self, definition):
        """validate the input stanza"""
        input_module.validate_input(self, definition)

    def collect_events(self, ew):
        """write out the events"""
        input_module.collect_events(self, ew)

    def get_account_fields(self):
        account_fields = []
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        checkbox_fields.append("collect_allowed_connections")
        checkbox_fields.append("collect_data")
        return checkbox_fields

    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, 'global_checkbox_param.json')
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, 'r') as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as e:
                self.log_error('Get exception when loading global checkbox parameter names. ' + str(e))
                self.global_checkbox_fields = []
        return self.global_checkbox_fields

if __name__ == "__main__":
    exitcode = ModInputguardicore_centra().run(sys.argv)
    sys.exit(exitcode)