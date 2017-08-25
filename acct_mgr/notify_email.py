import os
import re
import smtplib
from subprocess import Popen, PIPE

from genshi.builder import tag

from trac import __version__
from trac.core import *
from trac.util.html import to_fragment
from trac.util.translation import _, deactivate, reactivate, tag_
from trac.util.text import CRLF
from trac.notification.api import NotificationSystem

MAXHEADERLEN = 76
EMAIL_LOOKALIKE_PATTERN = (
        # the local part
        r"[a-zA-Z0-9.'+_-]+" '@'
        # the domain name part (RFC:1035)
        '(?:[a-zA-Z0-9_-]+\.)+' # labels (but also allow '_')
        '[a-zA-Z](?:[-a-zA-Z\d]*[a-zA-Z\d])?' # TLD
        )


class NotifyEmail(object):
    """Baseclass for notification by email."""

    from_email = 'trac+tickets@localhost'
    subject = ''
    template_name = None
    nodomaddr_re = re.compile(r'[\w\d_\.\-]+')
    addrsep_re = re.compile(r'[;\s,]+')

    def __init__(self, env):
        self.env = env
        self.config = env.config

        from trac.web.chrome import Chrome
        self.template = Chrome(self.env).load_template(self.template_name,
                                                       method='text')
	self.data = Chrome(self.env).populate_data(None, {'CRLF': CRLF})

        addrfmt = EMAIL_LOOKALIKE_PATTERN
        admit_domains = self.env.config.get('notification', 'admit_domains')
        if admit_domains:
            pos = addrfmt.find('@')
            domains = '|'.join([x.strip() for x in \
                                admit_domains.replace('.','\.').split(',')])
            addrfmt = r'%s@(?:(?:%s)|%s)' % (addrfmt[:pos], addrfmt[pos+1:],
                                              domains)
        self.shortaddr_re = re.compile(r'\s*(%s)\s*$' % addrfmt)
        self.longaddr_re = re.compile(r'^\s*(.*)\s+<\s*(%s)\s*>\s*$' % addrfmt)
        self._init_pref_encoding()
        domains = self.env.config.get('notification', 'ignore_domains', '')
        self._ignore_domains = [x.strip() for x in domains.lower().split(',')]
        # Get the name and email addresses of all known users
        self.name_map = {}
        self.email_map = {}
        for username, name, email in self.env.get_known_users():
            if name:
                self.name_map[username] = name
            if email:
                self.email_map[username] = email

    def _init_pref_encoding(self):
        from email.Charset import Charset, QP, BASE64, SHORTEST
        self._charset = Charset()
        self._charset.input_charset = 'utf-8'
        self._charset.output_charset = 'utf-8'
        self._charset.input_codec = 'utf-8'
        self._charset.output_codec = 'utf-8'
        pref = self.env.config.get('notification', 'mime_encoding').lower()
        if pref == 'base64':
            self._charset.header_encoding = BASE64
            self._charset.body_encoding = BASE64
        elif pref in ['qp', 'quoted-printable']:
            self._charset.header_encoding = QP
            self._charset.body_encoding = QP
        elif pref == 'none':
            self._charset.header_encoding = SHORTEST
            self._charset.body_encoding = None
        else:
            raise TracError(_('Invalid email encoding setting: %(pref)s',
                              pref=pref))

    def get_recipients(self, resid):
        """Return a pair of list of subscribers to the resource 'resid'.
        First list represents the direct recipients (To:), second list
        represents the recipients in carbon copy (Cc:).
        """
	raise NotImplementedError

    def notify(self, resid, subject, author=None):
        self.subject = subject
        config = self.config['notification']
        if not config.getbool('smtp_enabled'):
            return
        from_email, from_name = '', ''
        if author and config.getbool('smtp_from_author'):
            from_email = self.get_smtp_address(author)
            if from_email:
                from_name = self.name_map.get(author, '')
                if not from_name:
                    mo = self.longaddr_re.search(author)
                    if mo:
                        from_name = mo.group(1)
        if not from_email:
            from_email = config.get('smtp_from')
            from_name = config.get('smtp_from_name') or self.env.project_name
        self.replyto_email = config.get('smtp_replyto')
        self.from_email = from_email or self.replyto_email
        self.from_name = from_name
        if not self.from_email and not self.replyto_email:
            message = tag(
                tag.p(_('Unable to send email due to identity crisis.')),
                # convert explicitly to `Fragment` to avoid breaking message
                # when passing `LazyProxy` object to `Fragment`
                tag.p(to_fragment(tag_(
                    "Neither %(from_)s nor %(reply_to)s are specified in the "
                    "configuration.",
                    from_=tag.strong('[notification] smtp_from'),
                    reply_to=tag.strong('[notification] smtp_replyto')))))
            raise TracError(message, _('SMTP Notification Error'))

        torcpts, ccrcpts = self.get_recipients(resid)
        self.send(torcpts, ccrcpts)

    _mime_encoding_re = re.compile(r'=\?[^?]+\?[bq]\?[^?]+\?=', re.IGNORECASE)

    def format_header(self, key, name, email=None):
        from email.Header import Header
        maxlength = MAXHEADERLEN-(len(key)+2)
        # Do not sent ridiculous short headers
        if maxlength < 10:
            raise TracError(_("Header length is too short"))
        # when it matches mime-encoding, encode as mime even if only
        # ascii characters
        header = None
        if not self._mime_encoding_re.search(name):
            try:
                tmp = name.encode('ascii')
                header = Header(tmp, 'ascii', maxlinelen=maxlength)
            except UnicodeEncodeError:
                pass
        if not header:
            header = Header(name.encode(self._charset.output_codec),
                            self._charset, maxlinelen=maxlength)
        if not email:
            return header
        else:
            header = str(header).replace('\\', r'\\') \
                                .replace('"', r'\"')
            return '"%s" <%s>' % (header, email)

    def add_headers(self, msg, headers):
        for h in headers:
            msg[h] = self.encode_header(h, headers[h])

    def get_smtp_address(self, address):
        if not address:
            return None

        def is_email(address):
            pos = address.find('@')
            if pos == -1:
                return False
            if address[pos+1:].lower() in self._ignore_domains:
                return False
            return True

        if address == 'anonymous':
            return None
        if address in self.email_map:
            address = self.email_map[address]
        elif not is_email(address) and NotifyEmail.nodomaddr_re.match(address):
            if self.config.getbool('notification', 'use_short_addr'):
                return address
            domain = self.config.get('notification', 'smtp_default_domain')
            if domain:
                address = "%s@%s" % (address, domain)
            else:
                self.env.log.info("Email address w/o domain: %s", address)
                return None

        mo = self.shortaddr_re.search(address)
        if mo:
            return mo.group(1)
        mo = self.longaddr_re.search(address)
        if mo:
            return mo.group(2)
        self.env.log.info("Invalid email address: %s", address)
        return None

    def encode_header(self, key, value):
        if isinstance(value, tuple):
            return self.format_header(key, value[0], value[1])
        mo = self.longaddr_re.match(value)
        if mo:
            return self.format_header(key, mo.group(1), mo.group(2))
        return self.format_header(key, value)

    def send(self, torcpts, ccrcpts, mime_headers={}):
        from email.MIMEText import MIMEText
        from email.Utils import formatdate
        stream = self.template.generate(**self.data)
        # don't translate the e-mail stream
        t = deactivate()
        try:
            body = stream.render('text', encoding='utf-8')
        finally:
            reactivate(t)
        public_cc = self.config.getbool('notification', 'use_public_cc')
        headers = {}
        headers['X-Mailer'] = 'Trac %s, by Edgewall Software' % __version__
        headers['X-Trac-Version'] =  __version__
        headers['X-Trac-Project'] =  self.env.project_name
        headers['X-URL'] = self.env.project_url
        headers['Precedence'] = 'bulk'
        headers['Auto-Submitted'] = 'auto-generated'
        headers['Subject'] = self.subject
        headers['From'] = (self.from_name, self.from_email) if self.from_name \
                          else self.from_email
        headers['Reply-To'] = self.replyto_email

        def build_addresses(rcpts):
            """Format and remove invalid addresses"""
            return filter(lambda x: x, \
                          [self.get_smtp_address(addr) for addr in rcpts])

        def remove_dup(rcpts, all):
            """Remove duplicates"""
            tmp = []
            for rcpt in rcpts:
                if not rcpt in all:
                    tmp.append(rcpt)
                    all.append(rcpt)
            return (tmp, all)

        toaddrs = build_addresses(torcpts)
        ccaddrs = build_addresses(ccrcpts)
        accparam = self.config.get('notification', 'smtp_always_cc')
        accaddrs = accparam and \
                   build_addresses(accparam.replace(',', ' ').split()) or []
        bccparam = self.config.get('notification', 'smtp_always_bcc')
        bccaddrs = bccparam and \
                   build_addresses(bccparam.replace(',', ' ').split()) or []

        recipients = []
        (toaddrs, recipients) = remove_dup(toaddrs, recipients)
        (ccaddrs, recipients) = remove_dup(ccaddrs, recipients)
        (accaddrs, recipients) = remove_dup(accaddrs, recipients)
        (bccaddrs, recipients) = remove_dup(bccaddrs, recipients)

        # if there is not valid recipient, leave immediately
        if len(recipients) < 1:
            self.env.log.info("no recipient for a ticket notification")
            return

        pcc = accaddrs
        if public_cc:
            pcc += ccaddrs
            if toaddrs:
                headers['To'] = ', '.join(toaddrs)
        if pcc:
            headers['Cc'] = ', '.join(pcc)
        headers['Date'] = formatdate()
        msg = MIMEText(body, 'plain')
        # Message class computes the wrong type from MIMEText constructor,
        # which does not take a Charset object as initializer. Reset the
        # encoding type to force a new, valid evaluation
        del msg['Content-Transfer-Encoding']
        msg.set_charset(self._charset)
        self.add_headers(msg, headers)
        self.add_headers(msg, mime_headers)
        NotificationSystem(self.env).send_email(self.from_email, recipients, msg.as_string())

