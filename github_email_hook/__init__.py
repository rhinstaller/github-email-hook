# Shared methods for the github email hook and cron job
#
# Copyright (C) 2015 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#
# Author(s): David Shea <dshea@redhat.com>

import os
import requests
import threading
import smtplib
import pymongo
from email.mime.text import MIMEText

from github_email_hook.constants import DB_NAME, PULL_REQUEST_COLLECTION

def send_email(msg):
    """ Send a email.message object """

    # Fill in the to address
    del msg['To']
    msg['To'] = os.environ['GHEH_EMAIL_TO']

    # Add an Approved header if requested
    if 'GHEH_EMAIL_APPROVED' in os.environ:
        msg['Approved'] = os.environ['GHEH_EMAIL_APPROVED']

    if 'GHEH_SMTP_PORT' in os.environ:
        smtp_port = os.environ['GHEH_SMTP_PORT']
    elif os.environ.get('GHEH_SMTP_TLS', False):
        smtp_port = 587
    else:
        smtp_port = 25

    def _send_email(msg):
        s = smtplib.SMTP(os.environ['GHEH_SMTP_SERVER'], port=smtp_port)

        if os.environ.get('GHEH_SMTP_TLS', False):
            s.starttls()
            # Resend EHLO over TLS
            s.ehlo()

        if 'GHEH_SMTP_USER' in os.environ and 'GHEH_SMTP_PASSWORD' in os.environ:
            s.login(os.environ['GHEH_SMTP_USER'], os.environ['GHEH_SMTP_PASSWORD'])

        s.send_message(msg)
        print("Message %s sent" % msg['Message-Id'])

    # Don't hold up the web service while email is going
    email_thread = threading.Thread(target=_send_email, args=(msg,))
    email_thread.start()

def get_github(url, etag=None):
    """ Retrieve a URL from github

        Returns a requests.Response object
    """

    if 'GHEH_GITHUB_OAUTH' in os.environ:
        headers = {'Authorization': 'token %s' % os.environ['GHEH_GITHUB_OAUTH']}
    else:
        headers = {}

    if etag:
        headers.update({'If-None-Match': etag})

    return requests.get(url, headers=headers)

def pull_request_msg_id(pull_request):
    """ Generate a message ID from a pull_request json object.

        The ID generated will be of the form:
        pull-request.<id>.<head.sha>@<base.ref>.<base.id>
    """

    return "pull-request.%s.%s@%s.%s" % \
            (pull_request["id"], pull_request["head"]["sha"],
             pull_request["base"]["ref"], pull_request["base"]["repo"]["id"])

def patch_msg_id(pull_request, patch_sha):
    """ Generate a message ID for a patch within a pull request. """

    return "patch.%s.%s.%s@%s.%s" % \
            (pull_request["id"], pull_request["head"]["sha"], patch_sha,
             pull_request["base"]["ref"], pull_request["base"]["repo"]["id"])

def email_footer(url, msg_type="pull request"):
    """ Return a footer with a link to the pull request.

        url should contain the link.
    """

    return "\n-- \nTo view this %s on github, visit %s" % (msg_type, url)

def handle_commit_comment(data):
    """ Handle a commit comment event.

        This event is triggered by commit comments on commits in *our* repo.
        Commit comments on the copy of the commit in *their* repo are handled
        by the cron job, because we can't get push events for thos.
    """

    # TODO Message-Id

    # Find the pull request that this commit is part of, if any
    client = pymongo.MongoClient(os.environ[os.environ["GHEH_DB_ENVVAR"]])
    db = client[DB_NAME]
    pull_request_coll = db[PULL_REQUEST_COLLECTION]
    record = pull_request_coll.find_one({'commit_list.sha': data['comment']['commit_id']})

    if not record:
        # TODO maybe do something with comments outside a pull request at some
        # point. I dunno.
        return

    # Find the record for the commit itself
    commit = [c for c in record['commit_list'] if c['sha'] == data['comment']['commit_id']][0]

    # Re-create the patch subject
    subject = "Re: [PATCH %d/%d] %s" % \
            (record['commit_list'].index(commit) + 1, len(record['commit_list']),
             commit['commit']['message'].split('\n')[0])

    from_addr = "%s <%s>" % (data["comment"]["user"]["login"], os.environ["GHEH_EMAIL_FROM"])

    if data["comment"]["line"]:
        # TODO maybe fetch the file and try to create some context
        body = "In reply to line %d of %s:\n\n" % (data["comment"]["line"], data["comment"]["path"])
    else:
        body = ""

    body += data["comment"]["body"]
    body += '\n' + email_footer(data["comment"]["html_url"], msg_type="comment")

    msg = MIMEText(body)
    msg['From'] = from_addr
    msg['Subject'] = subject
    msg['In-Reply-To'] = patch_msg_id(record['pull_request'], commit['sha'])
    send_email(msg)

