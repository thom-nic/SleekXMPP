'''
Created on Jul 1, 2010

@author: bbeggs
'''
from . import base
import logging
import threading
import time
import random
import base64
from .. xmlstream.stanzabase import ElementBase, ET, JID
from sleekxmpp.stanza.error import Error
from sleekxmpp.stanza.iq import Iq
from sleekxmpp.xmlstream.handler.xmlcallback import XMLCallback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask
from xml.etree.ElementTree import tostring

XMLNS = 'http://jabber.org/protocol/ibb'

def sendAckIQ(xmpp, to, id):
    iq = xmpp.makeIqResult(id=id)
    iq['to'] = to
    iq.send(priority=1)
    
def sendCloseStream(xmpp, to, sid):
    close = ET.Element('{%s}close' %XMLNS, sid=sid)
    iq = xmpp.makeIqSet()
    iq['to'] = to
    iq.setPayload(close)
    iq.send(priority=1)
    
def generateSid():
    sid = ''
    for i in range(7):
        sid+=hex(int(random.random()*65536*4096))[2:]
    return sid[:8].upper()


class xep_0047(base.base_plugin):
    '''
    In-band file transfer for __xmpp.
    
    Both message and iq transfer is supported with message being attempted first.
    '''
       
    def plugin_init(self):
        self.xep = 'xep-047'
        self.description = 'in-band file transfer'
        self.acceptTransfers = self.config.get('acceptTransfers', True)
        self.saveDirectory = self.config.get('saveDirectory', '/tmp')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0047_')
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq')
        self.maxSessions = self.config.get('maxSessions', 1)
        
        #thread setup
        self.streamSessions = {} #id:thread
        
        #add handlers to listen for incoming requests
        self.xmpp.add_handler("<iq type='set'><open xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleIncomingTransferRequest, threaded=True)
        self.xmpp.add_handler("<iq type='set'><close xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleStreamClosed, threaded=False)
        
    def post_init(self):
        self.post_inited = True
        
    def sendFile(self, filePath, threaded=True):
        '''
        This method will block until timeout is reached waiting for a response
        from the receipent.
        The receiver will either:
        A) acknowledge the transfer and a session will start returnning the sid
        B) deny the transfer and this method will throw an exception 
        
        The returned sid can be used to check on the status of the transfer or cancel it.
        '''
        #TODO use this method to send a file
        logging.debug("About to send file: %s" %filePath)   
        #send the open request
    
    def getSendStatus(self, sid):
        '''
        Returns the status of the transfer specified by the sid
        '''
        #TODO: implement this method and figure out the return type, just just a dict of items.
    
    def cancelSend(self, sid):
        '''
        cancels an outgoing file transfer
        '''
        #TODO: implement canceling a file transfer
        
    def _handleIncomingTransferRequest(self, xml):
        logging.debug("incoming request to open file transfer stream")
        logging.debug(tostring(xml))
        if self.acceptTransfers and len(self.streamSessions) < self.maxSessions:
            elem = xml.find('{%s}' %XMLNS + 'open')
            self.streamSessions[elem.get('sid')] = ByteStreamSession(xmpp=self.xmpp, sid=elem.get('sid'), otherPartyJid=xml.get('from'))
            self.streamSessions[elem.get('sid')].start()
            sendAckIQ(xmpp=self.xmpp, to=xml.get('from'), id=xml.get('id'))
        else: #let the requesting party know we are not accepting file transfers 
            iq = self.xmpp.makeIqError(id=xml.get('id'))
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.setCondition('not-acceptable')
            iq.send(priority=1)
        
    def _handleStreamClosed(self, xml):
        '''
        Called when a stream closed event is received.
        '''
        elem = xml.find('{%s}' %XMLNS + 'close')
        sid = elem.get('sid')
        
        if self.streamSessions.get(sid):
            session = self.streamSessions.get(sid)
            del self.streamSessions[sid]
            session.handleEndStream()
            session.join(5)
            del session
            sendAckIQ(self.xmpp, xml.get('from'), xml.get('id'))
        else: #We don't know about this stream, send error
            iq = self.xmpp.makeIqError(id=xml.get('id'))
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.setCondition('item-not-found')
            iq.send(priority=1)
        
class ByteStreamSession(threading.Thread):
    
    def __init__(self, xmpp, sid, otherPartyJid):
        threading.Thread.__init__(self, name='bytestream_session_%s' %sid)
        self.processPackets = True
        self.__xmpp = xmpp
        self.__sid = sid
        self.__payloads = []
        self.__incSeqId = -1
        self.__outSeqId = -1
        self.__incSeqLock = threading.Lock()
        self.__outSeqLock = threading.Lock()
        
        self.otherPartyJid = otherPartyJid
        #register to start receiving file packets
        self.__xmpp.registerHandler(XMLCallback('file_receiver_message_%s' %self.__sid, MatchXMLMask("<message><data xmlns='%s' sid='%s' /></message>" %(XMLNS, self.__sid)), self._handlePacket, False, False, False))
        self.__xmpp.registerHandler(XMLCallback('file_receiver_iq_%s' %self.__sid, MatchXMLMask("<iq type='set'><data xmlns='%s' sid='%s' /></iq>" %(XMLNS, self.__sid)), self._handlePacket, False, False, False))
    
    def run(self):
        while self.processPackets:
            logging.debug("packet processing for __sid %s" %self.__sid)
            time.sleep(2)
            #TODO: add packet processing logic

        logging.debug("finished processing packets")
        
    def getNextIncSeqId(self):
        with self.__incSeqLock:
            self.__incSeqId += 1
            return self.__incSeqId
    
    def getNextOutSeqId(self):
        with self.__outSeqLock:
            self.__outSeqId += 1
            return self.__outSeqId
        
    def _handlePacket(self, xml):
        #ensure the data packet is from the other party we are conversing with
        if xml.get('id') == self.otherPartyJid:
            elem = xml.find('{%s}' %XMLNS + 'data')
            self.__payloads.append(elem.text)
            
            if 'iq' in xml.tag.lower():
                self.sendAckIQ(self.__xmpp, xml.get('from'), xml.get('id'))
        else:
            #Ignore the input... Should we close the stream, something is wrong
            #if we get a packet from a different user on this byte stream.  Could
            #possibly be an attack
            pass
      
    def handleEndStream(self):
        logging.debug("end of stream. remove data handlers")
        #remove the file handlers, stream has ended
        self.__xmpp.removeHandler('file_receiver_message_%s' %self.__sid)
        self.__xmpp.removeHandler('file_receiver_iq_%s' %self.__sid)
        #TODO: signal the thread runner to assemble the packets and save the file
        self.processPackets = False
        
    def getStatus(self):
        pass
    
    def cancelStream(self):
        pass
