#!/usr/bin/env python3

from pyln.client import Plugin
import sys


plugin = Plugin()


@plugin.async_method('hold-rpc-call')
def hold_rpc_call(plugin, request):
    """Simply never return, it should still get an error when the plugin crashes
    """


@plugin.hook('invoice_payment')
def on_invoice_payment(plugin, payment, **kwargs):
    print('payment received', payment)


plugin.run()
