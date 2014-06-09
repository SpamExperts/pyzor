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

License
-------

The project is licensed under the 
`GNU GPLv2 <http://www.gnu.org/licenses/gpl-2.0.html>`_ license.
