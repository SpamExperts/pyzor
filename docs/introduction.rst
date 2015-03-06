Introduction
==============

Pyzor is a collaborative, networked system to detect and block spam using 
digests of messages. 

Using Pyzor client a short digest is generated that is likely to uniquely 
identify the email message. This digest is then sent to a Pyzor server to:

 * check the number of times it has been reported as spam or whitelisted as 
   not-spam
 * report the message as spam
 * whitelist the message as not-spam

Since the entire system is released under the GPL, people are free to host 
their own independent servers. There is, however, a well-maintained and 
actively used public server available (courtesy of 
`SpamExperts <http://spamexperts.com>`_) at::

    public.pyzor.org:24441

Contribute
----------

- `Issue Tracker <http://github.com/SpamExperts/pyzor/issues>`_
- `Source Code <http://github.com/SpamExperts/pyzor>`_

Getting the source
------------------

To clone the repository using git simply run::

    git clone https://github.com/SpamExperts/pyzor

Please feel free to `fork us <https://github.com/SpamExperts/pyzor/fork>`_
and submit your pull requests.  

Running tests
-------------

The pyzor tests are split into *unittest* and *functional* tests.

*Unitests* perform checks against the current source code and **not**
the installed version of pyzor. To run all the unittests suite::

    env PYTHONPATH=. python tests/unit/__init__.py

*Functional* tests perform checks against the installed version of
pyzor and **not** the current source code. These are more extensive
and generally take longer to run. They also might need special setup.
To run the full suite of functional tests::

    env PYTHONPATH=. python tests/functional/__init__.py

There is also a `helper script <https://github.com/SpamExperts/
pyzor/blob/master/scripts/run_tests>`_ available that sets-up 
the testing enviroment, also taking into consideration the python 
version you are currently using::

    ./scripts/run_tests

.. note::

    The authentication details for the MySQL functional tests are taken from
    the `test.conf <https://github.com/SpamExperts/pyzor/blob/master/
    test.conf>`_ file.


License
-------

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License `version 2 <http://www.gnu.org/licenses/gpl-2.0.html>`_
only of the License.
