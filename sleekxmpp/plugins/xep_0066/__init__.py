"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2011 Nathanael C. Fritz, Lance J.T. Stout
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""

from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.stanza.iq import Iq

from sleekxmpp.plugins.xep_0066 import stanza
from sleekxmpp.plugins.xep_0066.stanza import OOB, OOBTransfer
from sleekxmpp.plugins.xep_0066.oob import XEP_0066


register_stanza_plugin(Iq, stanza.OOB)
register_stanza_plugin(Iq, stanza.OOBTransfer)


# Retain some backwards compatibility
xep_0066 = XEP_0066
