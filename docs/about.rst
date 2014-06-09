About
======

History
--------

Pyzor initially started out to be merely a Python implementation of Razor, but
due to the protocol and the fact that Razor's server is not Open Source or 
software libre, Frank Tobin decided to implement Pyzor with a new protocol and 
release the entire system as Open Source and software libre.

Protocol
----------

The central premise of Pyzor is that it converts an email message to a short 
digest that uniquely identifies the message. Simply hashing the entire message 
is an ineffective method of generating a digest, because message headers will 
differ when the content does not, and because spammers will often try to make 
a message unique by injecting random/unrelated text into their messages.

To generate a digest, the 2.0 version of the Pyzor protocol:

 * Discards all message headers.
 * If the message is greater than 4 lines in length:
 
  * Discards the first 20% of the message.
  * Uses the next 3 lines.
  * Discards the next 40% of the message.
  * Uses the next 3 lines.
  * Discards the remainder of the message.
  
 * Removes any 'words' (sequences of characters separated by whitespace) that are 10 or more characters long.
 * Removes anything that looks like an email address (X@Y).
 * Removes anything that looks like a URL.
 * Removes anything that looks like HTML tags.
 * Removes any whitespace.
 * Discards any lines that are fewer than 8 characters in length.
 
This is intended as an easy-to-understand explanation, rather than a technical one. 