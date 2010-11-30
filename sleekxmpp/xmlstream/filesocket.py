"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2010  Nathanael C. Fritz
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""

from socket import _fileobject
import socket


class FileSocket(_fileobject):

    """
    Create a file object wrapper for a socket to work around
    issues present in Python 2.6 when using sockets as file objects.

    The parser for xml.etree.cElementTree requires a file, but we will
    be reading from the XMPP connection socket instead.
    """
    def __init__(self, sock, mode='rb', bufsize=-1, close=False, runningEvent=None):
        _fileobject.__init__(self, sock, mode, bufsize, close)
        self.runningEvent = runningEvent
        
    def read(self, size=4096):
        """Read data from the socket as if it were a file."""
        data = None
        while not self.runningEvent.isSet():
            try:
                data = self._sock.recv(size)
                return data
            except Exception, e:
                #print('socket timeout')
                pass
            


class Socket26(socket._socketobject):

    """
    A custom socket implementation that uses our own FileSocket class
    to work around issues in Python 2.6 when using sockets as files.
    """

    def makefile(self, mode='r', bufsize=-1, runningEvent=None):
        """makefile([mode[, bufsize]]) -> file object
        Return a regular file object corresponding to the socket.  The mode
        and bufsize arguments are as for the built-in open() function."""
        return FileSocket(self._sock, mode, bufsize, runningEvent=runningEvent)
