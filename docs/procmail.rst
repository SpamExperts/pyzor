Procmail
=========

To use Pyzor in a procmail system, consider using the following simple recipe::

    :0 Wc
    | pyzor check
    :0 a
    pyzor-caught

If you prefer, you can merely add a header to message marked with Pyzor,  
instead of immediately filtering them into a separate folder::

    :0 Wc
    | pyzor check
    :0 Waf
    | formail -A 'X-Pyzor: spam'


