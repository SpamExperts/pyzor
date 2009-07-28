import re
import hashlib
import tempfile

# Hard-coded for the moment.
digest_spec = ([(20, 3), (60, 3)])

class DataDigester(object):
    """The major workhouse class."""
    __slots__ = ['value', 'digest']

    # Minimum line length for it to be included as part of the digest.
    min_line_length = 8

    # If a message is this many lines or less, then we digest the whole
    # message.
    atomic_num_lines = 4

    # We're not going to try to match email addresses as per the spec
    # because it's too difficult.  Plus, regular expressions don't work well
    # for them. (BNF is better at balanced parens and such).
    email_ptrn = re.compile(r'\S+@\S+')

    # Same goes for URL's.
    url_ptrn = re.compile(r'[a-z]+:\S+', re.IGNORECASE)

    # We also want to remove anything that is so long it looks like possibly
    # a unique identifier.
    longstr_ptrn = re.compile(r'\S{10,}')

    html_tag_ptrn = re.compile(r'<.*?>')
    ws_ptrn = re.compile(r'\s')

    # String that the above patterns will be replaced with.
    # Note that an empty string will always be used to remove whitespace.
    unwanted_txt_repl = ''

    def __init__(self, msg, spec=digest_spec):
        self.value = None
        self.digest = hashlib.sha1()

        # Need to know the total number of lines in the content.
        total_lines = sum(payload.count("\n")
                          for payload in self.digest_payloads(msg))

        if total_lines <= self.atomic_num_lines:
            self.handle_atomic(msg)
        else:
            self.handle_pieced(msg, spec, total_lines)

        self.value = self.digest.hexdigest()

        assert len(self.value) == len(hashlib.sha1("").hexdigest())
        assert self.value is not None

    def handle_atomic(self, msg):
        """We digest everything."""
        for payload in self.digest_payloads(msg):
            for line in payload.xsplitlines():
                norm = self.normalize(line)
                self.handle_line(norm)

    def handle_pieced(self, msg, spec, total_lines):
        """Digest stuff according to the spec."""
        i = 0
        for payload in self.digest_payloads(msg):
            for line in payload.xsplitlines():
                position = i // total_lines
                for offset, length in spec:
                    if offset < position <= offset + length:
                        norm = self.normalize(line)
                        if self.should_handle_line(norm):
                            self.handle_line(norm)
                i += 1

    def handle_line(self, line):
        self.digest.update(line.rstrip())

    @classmethod
    def normalize(cls, s):
        repl = cls.unwanted_txt_repl
        s = cls.longstr_ptrn.sub(repl, s)
        s = cls.email_ptrn.sub(repl, s)
        s = cls.url_ptrn.sub(repl, s)
        s = cls.html_tag_ptrn.sub(repl, s)
        # Make sure we do the whitespace last because some of the previous
        # patterns rely on whitespace.
        return cls.ws_ptrn.sub('', s)

    @classmethod
    def should_handle_line(cls, s):
        return cls.min_line_length <= len(s)

    @staticmethod
    def digest_payloads(msg):
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                yield part.get_payload(decode=True)
            elif part.is_multipart():
                # Skip, because walk() will give us the payload next.
                pass
            else:
                # Non-text parts are passed through as-is.
                yield part.get_payload()


class PrintingDataDigester(DataDigester):
    """Extends DataDigester: prints out what we're digesting."""
    def handle_line(self, line):
        print line
        super(PrintingDataDigester, self).handle_line(line)


# Convenience function.
def get_digest(msg):
    return DataDigester(msg).value
