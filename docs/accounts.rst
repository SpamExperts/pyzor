Accounts 
==========

Pyzor Accounts can be used to grant or restrict access to the Pyzor Server, by
ensuring the client are authenticated.

To get an account on a server requires coordination between the client user 
and server admin. Use the following steps:

 #. User and admin should agree on a username for the user. Allowed characters 
    for a username are alpha-numerics, the underscore, and dashes. 
    The normative regular expression it must match is ``^[-\.\w]+$``. Let us 
    assume they have agreed on *bob*.
 #. User generates a key with ``pyzor genkey``. Let us say that it generates 
    the salt,key of::
    
        227bfb58efaba7c582d9dcb66ab2063d38df2923,8da9f54058c34e383e997f45d6eb74837139f83b   
 
 #. Assuming the server is at ``127.0.0.1:9999``, the user puts the following  
    entry into ``~/.pyzor/accounts``::
    
        127.0.0.1 : 9999 : bob : 227bfb58efaba7c582d9dcb66ab2063d38df2923,8da9f54058c34e383e997f45d6eb74837139f83b
    
    This tells the Pyzor Client to use the *bob* account for server 
    ``127.0.0.1:9999``. It will still use the *anonymous* user for all other 
    servers.  
 #. The user then sends the key (the part to the right-hand side of the comma) 
    to the admin.
 #. The admin adds the key to their ``~/.pyzor/pyzord.passwd``:: 
        
        bob : 8da9f54058c34e383e997f45d6eb74837139f83b
 
 #. Assuming the admin wants to give the privilege of whitelisting (in addition 
    to the normal permissions), the admin then adds the appropriate permissions 
    to ``~/.pyzor/pyzord.access``:: 
    
        check report ping pong info whitelist : bob : allow
        
    For more information see :ref:`server-access-file`.   
 #. To reload the account and access information send the ``USR1`` signal to 
    the daemon.