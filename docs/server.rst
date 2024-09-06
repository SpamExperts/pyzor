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

This will require the `mysqlclient <https://pypi.org/project/mysqlclient/>`_ library and
subsequently the `libmariadb-dev` package.

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

Migrating
^^^^^^^^^^^

If you want to migrate your database from one engine to another there is an 
utility script installed with pyzor designed to do this. Note that the 
arguments are the equivalent of the ``Engine`` and ``DigestDB`` options. Some
usage examples: 

* Moving a database from gdbm to redis::

	pyzor-migrate --se gdbm --sd testdata/backup.db --de redis --dd localhost,6379,,0

* Moving a database from redis to MySQL::

	pyzor-migrate --se redis --sd localhost,6379,,0 --de mysql --dd localhost,root,,pyzor,public
 
.. _server-access-file:

Access File
-------------

This file can be used to restrict or grant access to various server-side 
operations to accounts. For more information on setting up accounts see 
`accounts`.

The format is very similar to the popular tcp_wrappers hosts.{allow,deny}:: 

	privilege ... : username ... : allow|deny

:privilege: a list of whitespace-separated commands The keyword ``all`` can
			be used to to refer to all commands.
:username: a list of whitespace-separated usernames. The keyword ``all`` 
		   can be used to refer to all users other than the anonymous
                   user. The anonymous user is refereed to as ``anonymous``.
:allow|deny: whether or not the specified user(s) can perform the specified 
			 privilege(s) on the line.

The file is processed from top to bottom, with the first match for 
user/privilege being the value taken. Every file has the following implicit 
final rule::

	all : all anonymous : deny

If this file is non-existant, the following default is used::

	check report ping pong info : anonymous : allow



