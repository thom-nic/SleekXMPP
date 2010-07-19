"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2007  Nathanael C. Fritz
    This file is part of SleekXMPP.

    SleekXMPP is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    SleekXMPP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SleekXMPP; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from __future__ import division, with_statement, unicode_literals
from . import base
import os, sys
import logging
import threading
import time
import random
import base64
from .. xmlstream.stanzabase import ET
from .. xmlstream.handler.xmlcallback import XMLCallback
from .. xmlstream.matcher.xmlmask import MatchXMLMask
from .. xmlstream.matcher.id import MatcherId
from .. xmlstream.handler.callback import Callback 
 
XMLNS = 'http://jabber.org/protocol/ibb'
STREAM_CLOSED_EVENT = 'BYTE_STREAM_CLOSED'
FILE_FINISHED_SENDING = 'BYTE_STREAM_SENDING_COMPLETE'
FILE_FINISHED_RECEIVING = 'BYTE_STREAM_RECEIVING_COMPLETE'

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
    In-band file transfer for xmpp.
    
    Currently only IQ transfer is supported
    
    Plugin will not accept a file transfer if the sender or recipient JID is the
    same as the currently logged in JID.
    
    Plugin configuration options:
    acceptTransfers        - Boolean     - Sets the plugin to either accept or deny transfers
    saveDirectory          - String      - The default directory that incoming file transfers will be saved in
    saveNamePrefix         - String      - Prefix that will be prepended to the saved file name of an incoming transfer
    overwriteFile          - Boolean     - If an incoming file transfer should overwrite a file if that file already exists
    stanzaType             - String      - Either IQ or message,  Currently only iq is supported
    maxSessions            - integer     - The max number of send/receive sessions that may run concurrently
    transferTimeout        - integer     - How long should a stream session wait between messages
    maxBlockSize           - integer     - Largest block size that a stream session should accept (limited by xmpp server)
    prefBlockSize          - integer     - The preferred block size for file transfer
    acceptTransferCallback - function ptr- This should be a function pointer that will return a boolean value letting the caller know if a 
                                           file transfer should or should not be accepted.  If this option is provided the maxSessions option is ignored.
    fileNameCallback       - function ptr- This should be a function pointer that will return a string with the full path and name a file should be saved as.  
                                           If the provided function pointer returns None or is not provided the default saveDirectory + saveNamePrefix_sid will be used.
                                           
    There are also 2 events that users of this plugin can register to receive notifications:
    FILE_FINISHED_SENDING     - This event is fired after a file send has completed
    FILE_FINISHED_RECEIVING   - This event is fired after an incoming file transfer has completed.
    
    !!!!!!!!!!!When registering to receive notifications about these events the
    callback functions should be registered as threaded!!!!!!!!!
    '''
       
    def plugin_init(self):
        self.xep = 'xep-047'
        self.description = 'in-band file transfer'
        self.acceptTransfers = self.config.get('acceptTransfers', True)
        self.saveDirectory = self.config.get('saveDirectory', '/tmp/')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0047_')
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq') #Currently only IQ is supported
        self.maxSessions = self.config.get('maxSessions', 2)
        self.transferTimeout = self.config.get('transferTimeout', 120) #how long we should wait between data messages until we consider the stream invalid
        self.maxBlockSize = self.config.get('maxBlockSize', 8192)
        self.prefBlockSize = self.config.get('prefBlockSize', 4096)
        #callbacks
        self.acceptTransferCallback = self.config.get('acceptTransferCallback')
        self.fileNameCallback = self.config.get('fileNameCallback')
        
        
        #thread setup
        self.streamSessions = {} #id:thread
        self.__streamSetupLock = threading.Lock()
        #add handlers to listen for incoming requests
        self.xmpp.add_handler("<iq type='set'><open xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleIncomingTransferRequest, threaded=True)
        self.xmpp.add_handler("<iq type='set'><close xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleStreamClosed, threaded=False)
        #Event handler to allow session threads to call back to the main processor to remove the thread
        self.xmpp.add_event_handler(STREAM_CLOSED_EVENT, self._eventCloseStream, threaded=True, disposable=False)
        
    def post_init(self):
        self.post_inited = True
        
    def sendFile(self, fileName, to, threaded=True):
        '''
        Sends a file to the intended receiver if the receiver is available and 
        willing to accept the transfer.  If the send is requested to be threaded 
        the session sid will be returned, otherwise the method will block until 
        the file has been sent and the session closed.
        
        The returned sid can be used to check on the status of the transfer or 
        cancel the transfer.
        
        Error Conditions:
        -IOError will be raised if the file to be sent is not found
        -TooManySessionsException will be raised if there are already more than 
        self.maxSessions running (configurable via plugin configuration)
        -Exception will be raised if the sender is not available
        -NotAcceptableException will be raised if the sender denies the transfer request
        or if the sender full JID is equal to the recipient 
        -InBandFailedException will be raised if there is an error during the
        file transfer
        '''
        #Init the stream with the recipient
        logging.debug("About to send file: %s" %fileName)   
        with self.__streamSetupLock:
            if len(self.streamSessions) > self.maxSessions:
                raise TooManySessionsException()
            
            if not os.path.isfile(fileName):
                raise IOError('file: %s not found' %fileName)
            
            if self.xmpp.fulljid == to:
                raise NotAcceptableException('Error setting up the stream, can not send file to ourselves %s', self.xmpp.fulljid)
            
            if not self.xmpp.state.ensure('connected'):
                raise Exception('Not connected to a server!')
            
            sid = generateSid()
            iq = self.xmpp.makeIqSet()
            iq['to'] = to
            openElem = ET.Element('{%s}open' %XMLNS, sid=sid, stanza=self.stanzaType)
            openElem.set('block-size', str(self.prefBlockSize))
            iq.setPayload(openElem)
            result = iq.send(block=True, timeout=10, priority=1)
            
            if result.get('type') == 'error': 
                if result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}service-unavailable') != None:
                    raise Exception('user not online! User: %s' %to)
                elif result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}not-acceptable') != None:
                    raise NotAcceptableException('Error setting up the stream, receiver not ready %s' %result)
                else:
                    raise Exception('Unknown error! %s' %result)
            
            self.streamSessions[sid] = ByteStreamSession(self.xmpp, sid, to, self.transferTimeout, self.prefBlockSize)
            
        self.streamSessions[sid].start()
        self.streamSessions[sid].sendFile(fileName, threaded)
        return sid
    
    def getSessionStatus(self, sid):
        '''
        Returns the status of the transfer specified by the sid.  If the session
        is not found none will be returned.
        '''
        session = self.streamSessions.get(sid)
        if session:
            return session.getStatus()
        else:
            return None
    
    def cancelSend(self, sid):
        '''
        cancels an outgoing file transfer.
        If the session is not found, method will pass
        '''
        session = self.streamSessions.get(sid)
        if session:
            session.cancelStream()
            
    def setAcceptStatus(self, status):
        '''
        sets if xep_0047 plugin will accept in-band file transfers or not.
        if switching from true to false any currently working sessions will 
        finish
        '''
        self.acceptTransfers = status
        
    def _handleIncomingTransferRequest(self, xml):
        logging.debug("incoming request to open file transfer stream")
        elem = xml.find('{%s}' %XMLNS + 'open')
        with self.__streamSetupLock:
            #Check the block size
            if(self.maxBlockSize < int(elem.get('block-size'))):
                iq = self.xmpp.makeIqError(id=xml.get('id'), condition='resource-constraint')
                iq['to'] = xml.get('from')
                iq['error']['type'] = 'modify'
                iq.send(priority=1)
                return
            
            #Check to see if the file transfer should be accepted
            acceptTransfer = False
            if self.acceptTransferCallback:
                acceptTransfer = self.acceptTransferCallback()
            else:
                if self.acceptTransfers and len(self.streamSessions) < self.maxSessions:
                    acceptTransfer = True
                    
            #Ask where to save the file if the callback is present
            #TODO: fix this to work with non linux 
            saveFileAs = self.saveDirectory + self.saveNamePrefix + elem.get('sid')
            if self.fileNameCallback:
                saveFileAs = self.fileNameCallback()
                
            #Do not accept a transfer from ourselves
            if self.xmpp.fulljid == xml.get('from'):
                acceptTransfer = False
            
            if acceptTransfer:
                self.streamSessions[elem.get('sid')] = ByteStreamSession(self.xmpp, elem.get('sid'), xml.get('from'), self.transferTimeout, int(elem.get('block-size')), saveFileAs)
                self.streamSessions[elem.get('sid')].start()
                sendAckIQ(xmpp=self.xmpp, to=xml.get('from'), id=xml.get('id'))
            else: #let the requesting party know we are not accepting file transfers 
                iq = self.xmpp.makeIqError(id=xml.get('id'), condition='not-acceptable')
                iq['to'] = xml.get('from')
                iq['error']['type'] = 'cancel'
                iq.send(priority=1)
        
    def _handleStreamClosed(self, xml):
        '''
        Called when a stream closed event is received.
        '''
        elem = xml.find('{%s}' %XMLNS + 'close')
        sid = elem.get('sid')
        
        if self.streamSessions.get(sid):
            with self.__streamSetupLock:
                session = self.streamSessions.get(sid)
                del self.streamSessions[sid]
                session.streamClosed = True
                session.process = False
                session.join(5)
                del session
                sendAckIQ(self.xmpp, xml.get('from'), xml.get('id'))
        else: #We don't know about this stream, send error
            iq = self.xmpp.makeIqError(id=xml.get('id'), condition='item-not-found')
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.send(priority=1)
            
    def _eventCloseStream(self, eventdata):
        '''
        Allows the session thread to 
        notify xep_0047 that a stream error has occurred or the stream has 
        finished and the session object should be disposed.
        '''
        with self.__streamSetupLock:
            session = self.streamSessions[eventdata['sid']]
            del self.streamSessions[eventdata['sid']]
            session.join(60)
            del session
        
        
class ByteStreamSession(threading.Thread):
    
    def __init__(self, xmpp, sid, otherPartyJid, timeout,  blockSize, recFileName = None):
        threading.Thread.__init__(self, name='bytestream_session_%s' %sid)
        #When we start the session the stream will already be open
        #and we will want to process the I/O
        self.process = True
        self.streamClosed = False
        
        self.__xmpp = xmpp
        self.__incSeqId = -1
        self.__outSeqId = -1
        self.__incSeqLock = threading.Lock()
        self.__outSeqLock = threading.Lock()
        self.__closeStreamLock = threading.Lock()
        self.__lastMessage = time.time()
        self.__incFile = None
        self.__sendThread = None
        self.__sendAckEvent = Event()
        
        #block size needs to be a multiple of 4 for base 64 encoding, step
        #the number down till it is divisible by 4 so we can fit in under the 
        #base64 encoded size
        while blockSize % 4 != 0:
            blockSize -= 1
        self.__blockSize = blockSize
        self.__fileReadSize = int(self.__blockSize / (4/3))
        
        self.sid = sid
        self.timeout = timeout
        self.recFileName = recFileName 
        
        self.otherPartyJid = otherPartyJid
        #register to start receiving file packets
        self.__xmpp.registerHandler(XMLCallback('file_receiver_message_%s' %self.sid, MatchXMLMask("<message><data xmlns='%s' sid='%s' /></message>" %(XMLNS, self.sid)), self._handlePacket, False, False, False))
        self.__xmpp.registerHandler(XMLCallback('file_receiver_iq_%s' %self.sid, MatchXMLMask("<iq type='set'><data xmlns='%s' sid='%s' /></iq>" %(XMLNS, self.sid)), self._handlePacket, False, False, False))
        
    def getSavedFileName(self):
        #TODO: this probably needs to be fixed up to work on OSes other than linux
        if self.recFileName:
            return self.recFileName
        else:
            return None
        
    def run(self):
        '''
        The Session will timeout of a message has not been received in more than 
        self.timeout seconds since the last message.
        
        This method takes care of opening the file for writing and ensuring that
        the file is closed, closing the stream if the session times out, and 
        ensuring that if a file is being sent that the send will quiesce properly.   
        '''
        if self.getSavedFileName():
            self.__incFile = open(self.getSavedFileName(), 'wb')
            
        while self.process:
            logging.debug("seconds since last message: %f" %self.__lastMessage)
            if time.time() - self.__lastMessage <= self.timeout: 
                time.sleep(2)
            else: # no file to send and the file transfer has timed out, close up the stream
                logging.info('file transfer timeout')
                self._closeStream()
                break
        
        logging.debug("end of stream. remove data handlers")
        #remove the file handlers, stream has ended
        self.__xmpp.removeHandler('file_receiver_message_%s' %self.sid)
        self.__xmpp.removeHandler('file_receiver_iq_%s' %self.sid)
        
        if self.__sendThread:
            self.__sendThread.join()
            del self.__sendThread
        
        #close the file hander 
        if self.__incFile:
            self.__xmpp.event(FILE_FINISHED_RECEIVING, {'sid': self.sid})
            self.__incFile.close()
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
        #and the data is in the correct order
        self.__lastMessage = time.time()
        elem = xml.find('{%s}' %XMLNS + 'data')
        logging.debug('packet size: %s' %len(elem.text) )
        nextSeqId = self.getNextIncSeqId()
        if self.process:
            if xml.get('from') == self.otherPartyJid and long(elem.get('seq')) == nextSeqId and len(elem.text) <= self.__blockSize:
                if self.__incFile: #write the file being sent if we have been giving somewhere to write it to
                    self.__incFile.write(base64.decodestring(elem.text))
                
                #for IQ stanzas we must return a result
                if 'iq' in xml.tag.lower():
                    sendAckIQ(self.__xmpp, xml.get('from'), xml.get('id'))
            else: 
                '''
                packet not in correct order or bad sender
                Ignore the input... Should we close the stream, something is wrong
                if we get a packet from a different user on this byte stream.  Could
                possibly be an attack
                ''' 
                logging.warning('Bad file transfer packet received! Terminating session with %s' %self.otherPartyJid)
                logging.error('seq #: %s expected seq: %i' %(elem.get('seq'), nextSeqId) )
                logging.error('packet size: %s' %len(elem.text))
                self.process = False
                self._closeStream()
                
    def getStatus(self):
        '''
        Returns an dict of the following items:
        sid                     - the sid of this session
        processing              - The processing state of this session
        otherPartyJID           - The other party we are swaping bytes with
        streamClosed            - If this ByteStream is closed or not
        lastMessageTimestamp    - The timestamp of the last received message (ack or data packet)
        incFileName (optional)  - if receiving a file, the full path and name of where the file is saved
        incFileKBytes (optional)- The number of KBytes currently received
        outFileKBytes (optional)- The number of bytes sent so far if sending a file
        '''
        status = {}
        status['sid'] = self.sid
        status['processing'] = self.process
        status['otherPartyJID'] = self.otherPartyJid
        status['streamClosed'] = self.streamClosed
        status['lastMessageTimestamp'] = self.__lastMessage
        if self.getSavedFileName():
            status['incFileName'] = self.getSavedFileName()
            status['incFileKBytes'] = self.__blockSize * self.__incSeqId
        if self.__sendThread:
            status['outFileKBytes'] = self.__fileReadSize * self.__outSeqId 
        return status
    
    def cancelStream(self):
        '''
        Cancels the current session with the other party and closes the stream.
        This should only be called when this sender wishes to cancel, and not when
        the other party cancels this session.
        '''
        self.process = False
        while self.isAlive():
            time.sleep(.5)
        self._closeStream()
        if self.getSavedFileName():
            os.remove(self.getSavedFileName())
        
    
    def sendFile(self, fileName, threaded=False):
        '''
        Sending a file always runs in it's own thread, but if threaded = False 
        this method will block until the sending is completed or canceled.  Only
        1 file may be sent per session.  
        '''
        if self.__sendThread:
            raise TooManySessionsException('Can only send 1 file per byte stream')

        self.__sendThread = threading.Thread(target=self._sendFile, name='Byte_Stream_Session_sender_%s' %self.sid,  kwargs={str('fileName'): fileName}) 
        self.__sendThread.start()
        
        if not threaded: #Block until the send is finished 
            self.__sendThread.join()
            
    def _sendFile(self, fileName):
        '''
        Does the actual work of sending a file, loops over the file breaking into
        the requested base64 encoded chunk size and sends it over the wire.  
        '''
        with open(fileName, 'rb') as file:
            self.__sendAckEvent.set()
            while self.process:
                if self.__sendAckEvent.wait(1): 
                    data = file.read(self.__fileReadSize)
                    if data == str(''): break
                    iq = self.__xmpp.makeIqSet()
                    dataElem = ET.Element('{%s}data' %XMLNS, sid=self.sid, seq=str(self.getNextOutSeqId()))
                    dataElem.text = base64.b64encode(data)
                    iq['to'] = self.otherPartyJid
                    iq.setPayload(dataElem)
                    self.__sendAckEvent.clear()
                    self.__xmpp.registerHandler(Callback('Bytestream_send_iq_matcher', MatcherId(iq['id']), self._sendFileAckHandler, thread=True, once=True, instream=False))
                    iq.send(block=False, priority=2)
                
        self.__xmpp.event(FILE_FINISHED_SENDING, {'sid': self.sid})
        self._closeStream()
        self.process = False
        
    def _sendFileAckHandler(self, xml):
        '''
        Callback for the id matcher for the last data packet sent to the other 
        party.  Once we receive an ack for our last data packet the __sendAckEvent
        is set so the sender can proceed with the next packet
        '''
        if xml.get('type') == 'result':
            self.__lastMessage = time.time()
            self.__sendAckEvent.set()
        else: #some kind of error occured
            self.process = False
            
            
    def _closeStream(self):
        '''
        This method is thread safe, and only callable once.  Use it to terminate
        the session with the other party
        '''
        with self.__closeStreamLock:
            if not self.streamClosed:
                self.streamClosed = True
                sendCloseStream(self.__xmpp, self.otherPartyJid, self.sid)
                self.__xmpp.event(STREAM_CLOSED_EVENT, {'sid': self.sid})
        
class InBandTransferException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class TooManySessionsException(InBandTransferException):
    def __init__(self, *args, **kwargs):
        InBandTransferException.__init__(self, *args, **kwargs)

class NotAcceptableException(InBandTransferException):
    def __init__(self, *args, **kwargs):
        InBandTransferException.__init__(self, *args, **kwargs)

def Event(*args, **kwargs):
    if sys.version_info < (2,7):
        return _Event(*args, **kwargs)
    else:
        return threading.Event(*args, **kwargs)

class _Event(object):

    #Modification of Event class from python 2.6 because the 2.7 version is better

    def __init__(self):
        self.__cond = threading.Condition(threading.Lock())
        self.__flag = False

    def isSet(self):
        return self.__flag

    is_set = isSet

    def set(self):
        self.__cond.acquire()
        try:
            self.__flag = True
            self.__cond.notify_all()
        finally:
            self.__cond.release()

    def clear(self):
        self.__cond.acquire()
        try:
            self.__flag = False
        finally:
            self.__cond.release()

    def wait(self, timeout=None):
        self.__cond.acquire()
        try:
            if not self.__flag:
                self.__cond.wait(timeout)
            return self.__flag
        finally:
            self.__cond.release()
