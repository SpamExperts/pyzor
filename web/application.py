#! /usr/bin/env python

import os
import email
import socket
import logging
import smtplib
import datetime
import email.utils
import ConfigParser
import email.mime.base
import email.mime.text
import email.mime.multipart

import flask

from flask_wtf.form import Form
from flask.views import MethodView
from wtforms.fields.simple import TextField, SubmitField, TextAreaField
from flask_wtf.html5 import EmailField
from flask_wtf.file import FileField
from flask_wtf.recaptcha.fields import RecaptchaField
from wtforms.validators import required, length

try:
    from raven.contrib.flask import Sentry
    from raven.handlers.logging import SentryHandler
except ImportError:
    pass

import pyzor
import pyzor.digest
import pyzor.client

MSG_TEMPLATE_TXT = """
Whitelist request:

    - Date: %s
    - Name: %%(name)s
    - Email: %%(email)s
    - Digest: %%(digest)s
    - Request IP: %%(ip)s

===============
%%(comment)s
===============

Pyzor Version: %s
""" % (datetime.datetime.utcnow(), pyzor.__version__)


def load_configuration():
    """Load server-specific configuration settings."""
    conf = ConfigParser.ConfigParser()
    defaults = {
        "captcha": {
            "ssl": "False",
            "public_key": "",
            "private_key": "",
        },
        "email": {
            "host": "localhost",
            "port": "25",
            "username": "",
            "password": "",
            "recipients": "",
            "sender": "no-reply@%s" % socket.gethostname(),
        },
        "logging": {
            "file": "/var/log/pyzor/web.log",
            "level": "INFO",
            "sentry": "",
            "sentry_level": "WARNING",
        }
    }
    # Load in default values.
    for section, values in defaults.iteritems():
        conf.add_section(section)
        for option, value in values.iteritems():
            conf.set(section, option, value)
    if os.path.exists("/etc/pyzor/web.conf"):
        # Overwrite with local values.
        conf.read("/etc/pyzor/web.conf")
    return conf


def setup_logging():
    logger = app.logger
    file_handler = logging.FileHandler(CONF.get("logging", "file"))
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s'))
    log_level = getattr(logging, CONF.get("logging", "level"))
    logger.setLevel(log_level)
    logger.addHandler(file_handler)
    raven_dsn = CONF.get("logging", "sentry")

    if raven_dsn:
        raven_log_level = getattr(logging, CONF.get("logging", "sentry_level"))
        sentry_handler = SentryHandler(raven_dsn)
        sentry_handler.setLevel(raven_log_level)
        logger.addHandler(sentry_handler)

app = flask.Flask(__name__)
CONF = load_configuration()
SENTRY_DSN = CONF.get("logging", "sentry")
setup_logging()
app.config.update({
    "RECAPTCHA_USE_SSL": CONF.get("captcha", "ssl").lower() == "true",
    "RECAPTCHA_PUBLIC_KEY": CONF.get("captcha", "public_key"),
    "RECAPTCHA_PRIVATE_KEY": CONF.get("captcha", "private_key"),
})

if SENTRY_DSN:
    sentry = Sentry(app, dsn=SENTRY_DSN)


class MessageForm(Form):
    digest = TextField("Pyzor digest*", validators=[length(40, 40,
                                                           "Invalid Digest"),
                                                    required()])
    message = FileField('Raw message*')
    name = TextField('Name')
    email = EmailField('Email')
    comment = TextAreaField('Other details')
    recaptcha = RecaptchaField()
    submit = SubmitField()

    def __init___(self, *args, **kwargs):
        super(MessageForm, self).__init__(*args, **kwargs)
        self.msg = None
        self.raw_message = None
        self.logger = app.logger

    def validate(self):
        if not Form.validate(self):
            return False
        self.raw_message = flask.request.files["message"].stream.read()
        try:
            digest = pyzor.digest.DataDigester(
                email.message_from_string(self.raw_message)).value
            if digest != self.digest.data:
                self.add_error("digest", "Digest does not match message.")
                return False
            client = pyzor.client.Client(timeout=20)
            try:
                response = client.check(digest)
            except pyzor.TimeoutError as e:
                self.add_error("message", "Temporary error please try again.")
                self.logger.warn("Timeout: %s", e)
                return False
            except pyzor.CommError as e:
                self.add_error("message", "Temporary error please try again.")
                self.logger.warn("Error: %s", e)
                return False
            if not response.is_ok():
                self.add_error("message", "Temporary error please try again.")
                self.logger.warn("Invalid response from server: %s", response)
                return False
            if int(response["Count"]) == 0:
                self.add_error("message", "Message not reported as spam.")
                return False
            if int(response["WL-Count"]) != 0:
                self.add_error("message", "Message is already whitelisted.")
                return False
        except AssertionError:
            self.add_error("message", "Invalid message.")
            return False
        return True

    def add_error(self, field, message):
        try:
            self.errors[field].append(message)
        except (KeyError, TypeError):
            self.errors[field] = [message]


class WhitelistMessage(MethodView):
    def __init__(self):
        self.form = MessageForm(flask.request.form, csrf_enabled=False)
        self.logger = app.logger

    def get(self):
        return flask.render_template('whitelist.html', form=self.form,
                                     error=None)

    def post(self):
        success = False
        if self.form.validate():
            msg = self.build_notification()
            self.send_email(msg)
            success = True
        return flask.render_template('whitelist.html', form=self.form,
                                     success=success)

    def build_notification(self):
        data = {"name": self.form.name.data,
                "email": self.form.email.data,
                "digest": self.form.digest.data,
                "comment": self.form.comment.data,
                "ip": flask.request.remote_addr}

        msg = email.mime.multipart.MIMEMultipart()
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Subject"] = "[Pyzor] Whitelist request"
        msg["From"] = CONF.get("email", "sender")
        msg["To"] = CONF.get("email", "recipients")
        msg.preamble = "This is a multi-part message in MIME format."
        msg.epilogue = ""
        msg.attach(email.mime.text.MIMEText(MSG_TEMPLATE_TXT % data))
        original_attachment = email.mime.base.MIMEBase("message", "rfc822")
        original_attachment.add_header("Content-Disposition", "attachment")
        original_attachment.set_payload(self.form.raw_message)
        msg.attach(original_attachment)
        return msg

    def send_email(self, msg):
        smtp = smtplib.SMTP(host=CONF.get("email", "host"),
                            port=CONF.get("email", "port"))
        smtp.ehlo()
        try:
            code, err = smtp.mail(CONF.get("email", "sender"))
            if code != 250:
                raise smtplib.SMTPSenderRefused(code, err,
                                                CONF.get("email", "sender"))
            rcpterrs = {}
            for rcpt in CONF.get("email", "recipients").split(","):
                code, err = smtp.rcpt(rcpt)
                if code not in (250, 251):
                    rcpterrs[rcpt] = (code, err)
            if rcpterrs:
                raise smtplib.SMTPRecipientsRefused(rcpterrs)
            code, err = smtp.data(msg.as_string())
            if code != 250:
                raise smtplib.SMTPDataError(code, err)
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPServerDisconnected:
                pass
app.add_url_rule("/whitelist/", view_func=WhitelistMessage.as_view("whitelist"))


@app.errorhandler(500)
def unhandled_exception(error):
    """Generic error message."""
    setup_logging()
    app.logger.error("Unhandled Exception: %s", error, exc_info=True)
    return flask.render_template('error.html', error=error)


if __name__ == '__main__':
    app.debug = True
    app.run()
