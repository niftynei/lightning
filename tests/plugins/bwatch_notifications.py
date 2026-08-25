#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()
events = []


@plugin.subscribe("bwatch_match")
def on_bwatch_match(plugin, bwatch_match, **kwargs):
    events.append({"type": "match", **bwatch_match})


@plugin.subscribe("bwatch_block_processed")
def on_bwatch_block_processed(plugin, bwatch_block_processed, **kwargs):
    events.append({"type": "processed", **bwatch_block_processed})


@plugin.subscribe("bwatch_block_reverted")
def on_bwatch_block_reverted(plugin, bwatch_block_reverted, **kwargs):
    events.append({"type": "reverted", **bwatch_block_reverted})


@plugin.method("listbwatchevents")
def list_bwatch_events():
    return {"events": events}


plugin.run()
