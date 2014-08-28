"""Handle digesting the messages."""

from __future__ import print_function

import re
import hashlib

try:
    import HTMLParser
except ImportError:
    import html.parser as HTMLParser

# Hard-coded for the moment.
digest_spec = ([(20, 3), (60, 3)])

HASH = hashlib.sha1
HASH_SIZE = len(HASH(b"").hexdigest())


class HTMLStripper(HTMLParser.HTMLParser):
    """Strip all tags from the HTML."""
    def __init__(self, collector):
        HTMLParser.HTMLParser.__init__(self)
        self.reset()
        self.collector = collector
        self.collect = True

    def handle_data(self, data):
        """Keep track of the data."""
        data = data.strip()
        if data and self.collect:
            self.collector.append(data)

    def handle_starttag(self, tag, attrs):
        HTMLParser.HTMLParser.handle_starttag(self, tag, attrs)
        if tag.lower() in ("script", "style"):
            self.collect = False

    def handle_endtag(self, tag):
        HTMLParser.HTMLParser.handle_endtag(self, tag)
        if tag.lower() in ("script", "style"):
            self.collect = True


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

    # Same goes for URLs.
    url_ptrn = re.compile(r'[a-z]+:\S+', re.IGNORECASE)

    # We also want to remove anything that is so long it looks like possibly
    # a unique identifier.
    longstr_ptrn = re.compile(r'\S{10,}')

    ws_ptrn = re.compile(r'\s')

    # String that the above patterns will be replaced with.
    # Note that an empty string will always be used to remove whitespace.
    unwanted_txt_repl = ''

    def __init__(self, msg, spec=None):
        if spec is None:
            spec = digest_spec
        self.value = None
        self.digest = HASH()

        # Need to know the total number of lines in the content.
        lines = []
        for payload in self.digest_payloads(msg):
            for line in payload.splitlines():
                norm = self.normalize(line)
                if self.should_handle_line(norm):
                    try:
                        lines.append(norm.encode("utf8", "ignore"))
                    except UnicodeError:
                        continue

        if len(lines) <= self.atomic_num_lines:
            self.handle_atomic(lines)
        else:
            self.handle_pieced(lines, spec)

        self.value = self.digest.hexdigest()

        assert len(self.value) == HASH_SIZE

    def handle_atomic(self, lines):
        """We digest everything."""
        for line in lines:
            self.handle_line(line)

    def handle_pieced(self, lines, spec):
        """Digest stuff according to the spec."""
        for offset, length in spec:
            for i in xrange(length):
                try:
                    line = lines[int(offset * len(lines) // 100) + i]
                except IndexError:
                    pass
                else:
                    self.handle_line(line)

    def handle_line(self, line):
        self.digest.update(line.rstrip())

    @classmethod
    def normalize(cls, s):
        repl = cls.unwanted_txt_repl
        s = cls.longstr_ptrn.sub(repl, s)
        s = cls.email_ptrn.sub(repl, s)
        s = cls.url_ptrn.sub(repl, s)
        # Make sure we do the whitespace last because some of the previous
        # patterns rely on whitespace.
        return cls.ws_ptrn.sub('', s).strip()

    @staticmethod
    def normalize_html_part(s):
        data = []
        stripper = HTMLStripper(data)
        try:
            stripper.feed(s)
        except (UnicodeDecodeError, HTMLParser.HTMLParseError):
            # We can't parse the HTML, so just strip it.  This is still
            # better than including generic HTML/CSS text.
            pass
        return " ".join(data)

    @classmethod
    def should_handle_line(cls, s):
        return len(s) and cls.min_line_length <= len(s)

    @classmethod
    def digest_payloads(cls, msg):
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                payload = part.get_payload(decode=True)

                charset = part.get_content_charset()
                errors = "ignore"
                if not charset:
                    charset = "ascii"
                elif (charset.lower().replace("_", "-") in ("quopri-codec",
                      "quopri", "quoted-printable", "quotedprintable")):
                    errors = "strict"

                try:
                    payload = payload.decode(charset, errors)
                except (LookupError, UnicodeError, AssertionError):
                    try:
                        payload = payload.decode("ascii", "ignore")
                    except UnicodeError:
                        continue
                if part.get_content_subtype() == "html":
                    yield cls.normalize_html_part(payload)
                else:
                    yield payload
            elif part.is_multipart():
                # Skip, because walk() will give us the payload next.
                pass
            else:
                # Non-text parts are passed through as-is.
                yield part.get_payload()


class PrintingDataDigester(DataDigester):
    """Extends DataDigester: prints out what we're digesting."""
    def handle_line(self, line):
        print(line.decode("utf8"))
        super(PrintingDataDigester, self).handle_line(line)
