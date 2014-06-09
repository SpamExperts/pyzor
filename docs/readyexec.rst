ReadyExec
==========

`ReadyExec <http://readyexec.sourceforge.net/>`_ is a system to eliminate the  
high startup-cost of executing scripts repeatedly. If you execute Pyzor a lot, 
you might be interested in installing ReadyExec and using it with Pyzor.

To use Pyzor with ReadyExec, the readyexecd.py server needs to be started as::

    readyexecd.py socket_file pyzor.client.run
    
``socket_file`` can be any (non-existing) filename you wish ReadyExec to use, 
such as /tmp/pyzor::

    readyexecd.py /tmp/pyzor pyzor.client.run
    
Individual clients are then executed as::

    readyexec socket_file options command cmd_options
    
For example::

    readyexec /tmp/pyzor check
    readyexec /tmp/pyzor report
    readyexec /tmp/pyzor whitelist --style=mbox
    readyexec /tmp/pyzor -d ping



