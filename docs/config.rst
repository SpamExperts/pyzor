Configuration
===============

The format of this file is INI-style (name=value, divided into [sections]). 
Names are case insensitive. All values which are filenames can have shell-style 
tildes (~) in them. All values which are relative filenames are interpreted to 
be relative to the Pyzor homedir. All of these options can be overridden by 
command-line arguments.

It is recommended to use the provided `sample configuration <https://github.co
m/SpamExperts/pyzor/blob/master/config/config.sample>`_. Simply copy it in 
pyzor's ``homedir``, remove the ``.sample`` from the name and alter any 
configurations you prefer.

.. _client-configuration:

client configuration
-----------------------

ServersFile
    Must contain a newline-separated list of server addresses to 
    report/whitelist/check with. All of these server will be contacted for 
    every operation.

AccountsFile
    File containing information about accounts on servers.

LogFile
    If this is empty then logging is done to stdout.

Timeout
    This options specifies the number of seconds that the pyzor client should 
    wait for a response from the server before timing out.

Style 
    Specify the message input style. See :ref:`client-input-style`.

ReportThreshold
    If the number of reports exceeds this threshold then the exit code of the 
    pyzor client is 0.

WhitelistThreshold
    If the number of whitelists exceed this threshold then exit code of the 
    pyzor client is 1.

.. _server-configuration:


server configuration
------------------------

Port
    Port to listen on.

ListenAddress
    Address to listen on.

LogFile
    File to contain server logs.

UsageLogFile
    File to contain server usage logs (information about each request).

PidFile
    This file contain the pid of the pyzord daemon when used with the 
    `--detach` option.

PasswdFile
    File containing a list of user account information. 

AccessFile
    File containing information about user privileges.

Engine
    Then engine type to be used for storage. See :ref:`server-engines`. 

DigestDB
    The database connection information. Format varies depending on the engine 
    used. See :ref:`server-engines`.

CleanupAge
    The maximum age of a record before it gets removed (in seconds). To 
    disable this set to 0.

Threads
    If set to true, the pyzor server will use multi-threading to serve 
    requests.

MaxThreads
    The maximum number of concurrent threads (0 means unlimited).

DBConnections
    The number of database connections kept opened by the server (0 means a 
    new one for each request). 
.. note::    
    `DBConnections` only applies to the MySQL engine.

Processes
    If set to true, the pyzor server will use multi-processing to serve 
    requests.

MaxProcesses
    The maximum number of concurrent processes (cannot be unlimited).


