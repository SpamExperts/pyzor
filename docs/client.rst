Pyzor Client
==============

The Pyzor Client is a Python script deployed with the package. It provides a 
command line interface to the Pyzor Client API::

	pyzor [options] command

You can also use the Python API directly to integrate Pyzor in your solution. 
For more information see :doc:`pyzor.client`.

Commands
----------

Check
^^^^^^

Checks the message read from stdin and prints the number of times it has been 
reported and the number of time it has been whitelisted. If multiple servers 
are listed in the configuration file each server is checked::

	$ pyzor check < spam.eml
	public.pyzor.org:24441	(200, 'OK')	134504	4681

The exit code will be:

 * 1 if the report count is 0 **or** the whitelist count is > 0
 * 0 if the report count is > 0 **and** the whitelist count is 0

Note that you can configure this behaviour by changing the report/whitelist 
thresholds from the configuration file or the command-line options. 
See :ref:`client-configuration`.

Info
^^^^^^

Prints detailed information about the message. The exit code will always be 
zero (0) if all servers returned (200, 'OK')::

	$ pyzor info < spam.eml
	public.pyzor.org:24441	(200, 'OK')
		Count: 134538
		Entered: Sat Jan  4 10:01:34 2014
		Updated: Mon Mar 17 12:52:04 2014
	WL-Count: 4681
		WL-Entered: Mon Jan  6 14:32:01 2014
		WL-Updated: Fri Mar 14 16:11:02 2014


Report
^^^^^^^^

Reports to the server a digest of each message as spam. Writes to standard 
output a tuple of (error-code, message) from the server. If multiple servers 
are listed in the configuration file the message is reported to each one::

	$ pyzor report < spam.eml
	public.pyzor.org:24441      (200, 'OK')

Whitelist
^^^^^^^^^^

Reports to the server a digest of each message as not-spam. Writes to standard 
output a tuple of (error-code, message) from the server. If multiple servers 
are listed in the configuration file the message is reported to each one::

	$ pyzor whitelist < spam.eml
	public.pyzor.org:24441      (200, 'OK')

.. note::

   This command is not available by default for the anonymous user.


Ping
^^^^^^

Merely requests a response from the servers::

	$ pyzor ping
	public.pyzor.org:24441      (200, 'OK')

Pong
^^^^^^

Can be used to test pyzor, this will always return a large number of reports 
and 0 whitelist, regardless of the message::

	$ pyzor pong < ham.eml
	public.pyzor.org:24441	(200, 'OK')	9223372036854775807	0

Predigest
^^^^^^^^^^^

Prints the message after the predigest phase of the pyzor algorithm::

	$ pyzor predigest < test.eml
	Thisisatest.

Digest
^^^^^^^^^

Prints the message digest, that will be sent to the server::

	$ pyzor digest < spam.eml
	c3a8e8d987f07843792d2ab1823b04cc3cb87482

Genkey
^^^^^^^^

Based upon a secret passphrase gathered from the user and randomly gathered 
salt, prints to standard output a tuple of "salt,key". Used to put account 
information into the accounts file.

Local Whitelist
^^^^^^^^^^^^^^^

Add a message to the local whitelist file, and therefore ignoring the digest 
and returning 0 reports for the digest without contacting the pyzor server:

    $ pyzor local_whitelist < false_positive.eml
    
Local UnWhitelist
^^^^^^^^^^^^^^^^^

Remove a message from the local whitelist file:

    $ pyzor local_unwhitelist < false_positive.eml
   


.. _client-server-file:

Servers File
--------------

This file contains a list of servers that will be contacted by the Pyzor 
client for every operation. If no servers are specified it defaults to the 
public server:: 

	public.pyzor.org:24441

The servers can also be specified as IP addresses, but they must always be 
followed by the port number.

For example having this in ``~/.pyzor/servers``::

 # This is comment
 public.pyzor.org:24441
 127.0.0.1:24441
 
Will configure the client to check both the public server and a local one::

	$ pyzor ping
	public.pyzor.org:24441  (200, 'OK')
	127.0.0.1:24441 (200, 'OK')
 

.. _client-input-style:

Input Style
--------------

Pyzor accepts messages in various forms. This can be controlled with the
*style* configuration or command line option. Currently support are:

 * msg - individual RFC5321 message
 * mbox - mbox file of messages 
 * digests - Pyzor digests, one per line


