Changelog
=========

Pyzor 1.0.1
-----------

Changed whitelist URL to app.pyzor.org/whitelist/

Pyzor 1.0.0
-----------

New features:

    * New pyzor commands ``local_[un]whitelist`` are available for managing 
      a local whitelist on the client side. (`#10 <https://github.com/SpamExperts/pyzor/issues/10>`_)
    * New ``PreFork`` option for the pyzor server. This allows creating multiple
      workers for handling pyzor requests. (`#26 <https://github.com/SpamExperts/pyzor/issues/26>`_)
      
Perfomance enhancements:

    * Improve usage of the Redis engine by using Hashes instead of string for
      storing digests. The migration tool can be used to update you current 
      database. (`#29 <https://github.com/SpamExperts/pyzor/issues/29>`_)

Others:

    * PyPy3 compatibility verified and introduced into the Travis-CI system. (`#24 <https://github.com/SpamExperts/pyzor/issues/24>`_)
    * Unification of the storage engines types. (`#30 <https://github.com/SpamExperts/pyzor/issues/30>`_)
    * Improved check on the public whitelisting request service to skip sending 
      requests to whitelist message that have not been reported to the public 
      database or have been already whitelisted. (`#27 <https://github.com/SpamExperts/pyzor/issues/27>`_)     


Pyzor 0.9.0
------------

Bug fixes:

	* Fix gdbm decoding issue. (`#20 <https://github.com/SpamExperts/pyzor/issues/20>`_)
	* Fix inconsistencies accounts and addresses. (`#22 <https://github.com/SpamExperts/pyzor/issues/22>`_)
	
New features:

	* Strip content inside ``<style>`` and `<script>` tags during HTML 
	  normalization. (`#19 <https://github.com/SpamExperts/pyzor/issues/19>`_)
 	* Improvements in Pyzor client error codes. (`#17 <https://github.com/SpamExperts/pyzor/issues/17>`_)
 	* Add support for logging to Sentry (`#7 <https://github.com/SpamExperts/pyzor/issues/7>`_)
      
Perfomance enhancements:

	* Do report and whitelist in a single step for MySQL Server Engine. 
	  (`#5 <https://github.com/SpamExperts/pyzor/issues/5>`_)
		  
      
Others:

	* You can now requests whitelisting a message by using a simple form 
	  available at: `http://public.pyzor.org/whitelist/ <http://public.pyzor.org/whitelist/>`_


Pyzor 0.8.0
--------------

Bug fixes:

	* Fix unicode decoding issues. (`#1 <https://github.com/SpamExperts/pyzor/issues/1>`_)
	
New features:

	* A new option for the pyzor server to set-up digest forwarding.
	* A new script ``pyzor-migrate`` is now available. The script allows 
	  migrating your digest database from one engine to another.   
	  (`#2 <https://github.com/SpamExperts/pyzor/issues/2>`_)
      
Perfomance enhancements:

	* Use multiple threads when connecting to multiple servers in the pyzor
	  client script. (`#5 <https://github.com/SpamExperts/pyzor/issues/5>`_)	  
	* A new ``BatchClient`` is available in pyzor client API. The client 
	  now send reports in batches to the pyzor server. 
	  (`#13 <https://github.com/SpamExperts/pyzor/issues/13>`_)
      
Others:

	* Small adjustments to the pyzor scripts to add Windows compatibility.
	* Automatically build documentation.
	* Continuous integration on `Travis-CI <https://travis-ci.org/SpamExperts/pyzor>`_.
	* Test coverage on `coveralls <https://coveralls.io/r/SpamExperts/pyzor?branch=master>`_.


Pyzor 0.7.0
--------------

Bug fixes:

	* Fix decoding bug when messages are badly formed
	* Pyzor now correctly creates the specified homedir, not the user's one

New features:

	* Logging is now disabled by default
 	* Automatically run 2to3 during installation (if required)

New pyzord features:

 	* Added ability to disable expiry
 	* New redis engine support has been added
 	* New option to enable gevent
 	* Added the ability to reload accounts and access files using USR1 signal
 	* Added the ability to safely stop the daemon with TERM signal
 	* Split the usage-log and normal log in two separate files
 	* Pyzord daemon can now daemonize and detach itself

Pyzor 0.6.0
--------------
	*	pyzor and pyzord will now work with Python3.3 (if 
		the the 2to3-3.3 is previously ran)
	*	pyzord and pyzor now supports IPv6 
	*	Improved handling of multi-threading (signals where 
		again removed) for the mysql engine
	* 	Introduced multi-processing capabilities
	* 	Improved HTML parsing
	*	Introduced self document sample configurations
	*	Introduced ability to set custom report/whitelist thresholds 
		for the pyzor client
	* 	Greatly improved tests coverage

Pyzor 0.5.0
---------------

Note that the majority of changes in this release were contributed back
from the Debian pyzor package.

	*	Man pages for pyzor and pyzord.
	*	Changing back to signals for database locking,
		rather than threads.  It is likely that signals
		will be removed again in the future, but the
		existing threading changes caused problems.
	*	Basic checks on the results of "discover".
	*	Extended mbox support throughout the library.
	*	Better handling on unknown encodings.
	*	Added a --log option to log to a file.
	*	Better handling of command-line options.
	*	Improved error handling.
