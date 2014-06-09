Pyzor Server
==============

The Pyzor Server will listen on the specified address and any serve request
from Pyzor Clients.

Daemon
------------

Starting
^^^^^^^^^

The Pyzor Server can be started as a daemon by using the ``--detach`` option. 
This will:

 * daemonize the script and detach from tty
 * create a pid file
 * redirect any output to the specified file
 
Example::

    $ pyzord --detach /dev/null --homedir=/home/user/.pyzor/
    
Stopping  
^^^^^^^^^

To safely stop the Pyzor Server you can use the ``TERM`` signal to trigger 
a safe shutdown::

   $ kill -TERM `cat /home/user/.pyzor/pyzord.pid`
   
Reloading
^^^^^^^^^^^

The reload signal will tell the Pyzor Server to reopen and read the access and
passwd files. This is useful when adding new accounts or changing the 
permissions for an existing account. This is done by sending the ``USR1`` 
signal to the process::

   $ kill -USR1 `cat /home/user/.pyzor/pyzord.pid`

.. _server-engines:
 
Engines
----------

The Pyzor Server supports a number of back-end database engines to store the
message digests.

Gdbm
^^^^^^^

This is the default engine, and the easiest to use and configure. But this it
is also highly inefficient and not recommended for servers that see a large 
number of requests. 

To use the the ``gdbm`` engine simply add to the config file 
``~/.pyzor/config``::

    [server]
    Engine = gdbm
    DigestDB = pyzord.db

The database file will be created if it didn't previously exists, and will be 
located as usual in the specified Pyzor homedir. 

For more information about GDBM see `<http://www.gnu.org.ua/software/gdbm/>`_.

MySQL
^^^^^^

This will require the `MySQL-python <https://pypi.python.org/pypi/MySQL-
python>`_ library. 

.. note::
   `MySQL-python` does not currently support Python 3
   
To configure the ``MySQL`` engine you will need to:

 * Create a MySQL database (for e.g. pyzor)
 * Create a MySQL table with the following schema::
    
    CREATE TABLE `digests` (
        `digest` char(40) default NULL,
        `r_count` int(11) default NULL,
        `wl_count` int(11) default NULL,
        `r_entered` datetime default NULL,
        `wl_entered` datetime default NULL,
        `r_updated` datetime default NULL,
        `wl_updated` datetime default NULL,
        PRIMARY KEY  (`digest`)
    )
  
 * Create a MySQL user 
 * Grant ``ALL PRIVILEGES`` to that user on the newly created table
 
To use the ``MySQL`` engine add to the configuration file:: 
  
    [server]
    Engine = mysql
    DigestDB = localhost,user,password,pyzor,digests
 
Redis
^^^^^^^

This will require the `redis <https://pypi.python.org/pypi/redis>`_ library.

To use the ``redis`` engine simply add to the configuration file::

    [server]
    Engine = redis
    DigestDB = localhost,6379,,0

Or if a password is required::

    [server]
    Engine = redis
    DigestDB = localhost,6379,password,0

In the example above the redis database used is 0. 
 
