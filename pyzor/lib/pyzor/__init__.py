import re
import sys
import sha
import tempfile
import random

proto_name    = 'pyzor'
proto_version =  '0.0'

class ProtocolError(Exception):
    pass

class TimeoutError(Exception):
    pass

class Singleton(object):
    __slots__ = []
    def __new__(cls, *args, **kwds):
        it = cls.__dict__.get('__it__')
        if it is None:
            cls.__it__ = object.__new__(cls)
        return cls.__it__


class Output(Singleton):
    do_debug = 0
    quiet    = 0
    def __init__(self, quiet=None, debug=None):
        if quiet is not None: self.quiet = quiet
        if debug is not None: self.do_debug = debug
    def data(self, msg):
        print msg
    def warn(self, msg):
        if not self.quiet: sys.__stderr__.write('%s\n' % msg)
    def debug(self, msg):
        if self.do_debug: sys.__stderr__.write('%s\n' % msg)


class PiecesDigest(str):
    # hex output doubles digest size
    value_size = sha.digest_size * 2
    
    bufsize = 1024

    # We're not going to try to match email addresses
    # as per the spec because it's too freakin difficult
    # Plus, regular expressions don't work well for them.
    # (BNF is better at balanced parens and such)
    email_ptrn = re.compile(r'\S+@\S+')

    # same goes for URL's
    url_ptrn = re.compile(r'[a-z]+:\S+', re.IGNORECASE)

    ws_ptrn = re.compile(r'\s')
    
    def __init__(self, value):
        if len(value) != self.value_size:
            raise ValueError, "invalid digest value size"
        super(PiecesDigest, self).__init__(value)

    def get_line_offsets(buf):
        cur_offset = 0
        offsets = []
        while 1:
            i = buf.find('\n', cur_offset)
            if i == -1:
                return offsets
            offsets.append(i)
            cur_offset = i + 1
            
    get_line_offsets = staticmethod(get_line_offsets)

    def normalize(self, s):
        s2 = s
        s2 = self.email_ptrn.sub('', s2)
        s2 = self.url_ptrn.sub('', s2)
        # make sure we do the whitespace last because some of
        # the previous patterns rely in whitespace
        s2 = self.ws_ptrn.sub('', s2)
        return s2
    
    normalize = classmethod(normalize)

    def compute_from_file(self, fp, spec, seekable=1):
        line_offsets = []

        if seekable:
            cur_offset = fp.tell()
            newfp = None
        else:
            # we need a seekable file because to make
            # line-based skipping around to be more efficient
            # than loading the whole thing into memory
            cur_offset = 0
            newfp = tempfile.TemporaryFile()

        while 1:
            buf = fp.read(self.bufsize)
            line_offsets.extend(map(lambda x: cur_offset + x,
                                    self.get_line_offsets(buf)))
            if not buf: break
            cur_offset += len(buf)
            
            if newfp:
                newfp.write(buf)

        if newfp:
            fp = newfp


        digest = sha.new()
        
        for (perc_offset, length) in spec:
            assert 0 <= perc_offset < 100

            offset = line_offsets[int(perc_offset/100 * len(line_offsets))]
            fp.seek(offset)

            i = 0
            while i < length:
                line = fp.readline()
                if not line: break
                norm_line = self.normalize(line)
                if not norm_line: continue
                digest.update(norm_line)
                i += 1

        return apply(self, (digest.hexdigest(),))
    
    compute_from_file = classmethod(compute_from_file)


class PiecesDigestSpec(list):
    __slots__ = []
    
    def netenc(self):
        return netlist(map(lambda x: ','.join(map(str, x)), self),
                       netstring)

    def from_netenc(self, f):
        new_spec = apply(self)

        for el in read_netlist(f, read_netstring):
            (perc_offset, length) = el.split(',', 2)
            perc_offset = int(perc_offset)
            length      = int(length)
            if not (0 <= perc_offset < 100):
                raise ValueError, "offset percentage out of bounds"
            if not length > 0:
                raise ValueError, "piece lengths must be positive"
            new_spec.append((perc_offset, length))
        
        return new_spec

    from_netenc = classmethod(from_netenc)


class Message(object):
    __slots__ = ['data', 'thread']

    def __init__(self, thread=None):
        if thread is None:
            thread = ThreadID.generate()
        self.thread = thread
        self.clear()

    def clear(self):
        self.data = ''

    def add_int(self, i):
        self.data += netint(i)

    def add_string(self, s):
        self.data += netstring(s)

    def add_netenc(self, s):
        """add some data that is already net-encoded"""
        self.data += s

    def __nonzero__(self):
        # XXX this should be moved to returning bool after
        # 2.2.1 is more wide-spread
        if self.data: return 1
        return 0

    def __str__(self):
        return netstring(proto_name) \
               + netstring(proto_version) \
               + netint(self.thread) \
               + self.data



class ThreadID(int):
    __slots__ = []
    # (0, 1024) is reserved
    full_range = (0, 2**16)
    ok_range   = (1024, full_range[1])
    
    def __init__(self, i):
        if not (self.full_range[0] <= i < self.full_range[1]):
            raise ValueError, "value outside of range"
        super(ThreadID, self).__init__(i)

    def generate(self):
        return apply(self, (apply(random.randrange, self.ok_range),))
    generate = classmethod(generate)


def netint(i):
    return "%u\n" % i


def read_netint(f):
    try:
        return int(f.readline())
    except ValueError, e:
        raise ProtocolError, e


def netstring(s):
    return "%s\n" % s


def read_netstring(f):
    line = f.readline()
    if not line:
        raise ProtocolError, "unexpected EOF"
    return line.splitlines()[0]

def netlist(l, factory):
    return netint(len(l)) + reduce(lambda x,y: x + factory(y), l, '')


def read_netlist(fp, factory):
    length = read_netint(fp)
    if not length >= 0:
        raise ProtocolError, "invalid length for netlist"
    l = []
    for i in range(0, length):
        l.append(apply(factory, (fp,)))

    return l
