#!/usr/bin/env python
#
# github to email bridge
#
# Copyright (C) 2015
# Red Hat, Inc.  All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author(s): David Shea <dshea@redhat.com>
#

# For use with mod_wsgi, though it could probably be run ok with the wsgiref
# httpd. Tested with python 3.3

import os
import json
import hmac
import hashlib
import email.parser
import pymongo

from email.mime.text import MIMEText

from github_email_hook import send_email, get_github, pull_request_msg_id, json_to_email_date
# The commit_comment handler is shared with the cron job
from github_email_hook import handle_commit_comment

from github_email_hook import patch_msg_id, email_footer
from github_email_hook.constants import PULL_REQUEST_COLLECTION

def application(environ, start_response):
    """ Entry point for mod_wsgi """

    # We always respond with text/plain no matter what, so set that
    response_headers = [('Content-Type', 'text/plain')]

    # Check that all the necessary environment variables are set
    if 'GHEH_SMTP_SERVER' not in os.environ or \
            'GHEH_EMAIL_TO' not in os.environ or \
            'GHEH_EMAIL_FROM' not in os.environ or \
            'GHEH_DB_ENVVAR' not in os.environ or \
            os.environ['GHEH_DB_ENVVAR'] not in os.environ or \
            'GHEH_DB_NAME' not in os.environ:
        print("Missing required environment variables", file=environ['wsgi.errors'])
        start_response('500 Internal Server Error', response_headers)
        return [b'Service not properly configured, please check that all mandatory environment variables are set']

    # Check that this request is the right kind of thing: a POST of type
    # application/json with a known length
    if environ['REQUEST_METHOD'] != 'POST':
        start_response('405 Method Not Allowed', response_headers)
        return [b'Only POST messages are accepted']

    if 'CONTENT_TYPE' not in environ or environ['CONTENT_TYPE'] != 'application/json':
        print("Invalid content-type %s" % environ.get('CONTENT_TYPE', None),
                file=environ['wsgi.errors'])
        start_response('415 Unsupported Media Type', response_headers)
        return [b'Requests must be of type application/json']

    try:
        content_length = int(environ['CONTENT_LENGTH'])
    except (KeyError, ValueError):
        start_response('411 Length required', response_headers)
        return [b'Invalid content length']

    # Look for the github headers
    if 'HTTP_X_GITHUB_EVENT' not in environ:
        print("Missing X-Github-Event", file=environ['wsgi.errors'])
        start_response('400 Bad Request', response_headers)
        return [b'Invalid event type']

    event_type = environ['HTTP_X_GITHUB_EVENT']

    # Read the post data
    # Errors will be automatically converted to a 500
    post_data = environ['wsgi.input'].read(content_length)

    # If a secret was set, validate the post data
    if 'GHEH_GITHUB_SECRET' in os.environ:
        if 'HTTP_X_HUB_SIGNATURE' not in environ:
            print("Missing signature", file=environ['wsgi.errors'])
            start_response('401 Unauthorized', response_headers)
            return [b'Missing signature']

        # Only sha1 is used currently
        if not environ['HTTP_X_HUB_SIGNATURE'].startswith('sha1='):
            print("Signature not sha1", file=environ['wsgi.errors'])
            start_response('401 Unauthorized', response_headers)
            return [b'Invalid signature']

        digester = hmac.new(os.environ['GHEH_GITHUB_SECRET'].encode('utf-8'),
                msg=post_data, digestmod=hashlib.sha1)
        if 'sha1=' + digester.hexdigest() != environ['HTTP_X_HUB_SIGNATURE']:
            print("Signature mismatch", file=environ['wsgi.errors'])
            start_response('401 Unauthorized', response_headers)
            return [b'Invalid signature']

    # Convert the post data to a string so we can start actually using it
    # JSON is required to be in utf-8, utf-16, or utf-32, but github only ever
    # uses utf-8, praise be, so just go ahead and assume that
    try:
        post_str = post_data.decode('utf-8')
    except UnicodeDecodeError:
        print("Unable to decode JSON", file=environ['wsgi.errors'])
        start_response('400 Bad Request', response_headers)
        return [b'Invalid data']

    # Parse the post data
    try:
        event_data = json.loads(post_str)
    except ValueError:
        print("Unable to parse JSON", file=environ['wsgi.errors'])
        start_response('400 Bad Request', response_headers)
        return [b'Invalid data']

    # Done with parsing the request, dispatch the data to the event handler
    if event_type == "pull_request":
        handle_pull_request(event_data)
    elif event_type == "issue_comment":
        handle_issue_comment(event_data)
    elif event_type == "pull_request_review_comment":
        handle_pull_request_review_comment(event_data)
    elif event_type == "commit_comment":
        handle_commit_comment(event_data)

    start_response('200 OK', response_headers)
    return [b'']

_parser = email.parser.Parser()
def read_message(url):
    """ Read a URL and parse the result as a email.message object 

        This will return a message with a content-transfer-encoding of 8bit,
        which doesn't work with smtplib, because computers are the worst.
        Once the payload is finished, it is up to the caller to encode the
        payload properly, for example by deleteing Content-Transfer-Encoding
        and setting the charset to utf-8.
    
    """

    response = get_github(url)
    if response.status_code != 200:
        raise ValueError("Unexpected status code %s" % response.status_code)

    return _parser.parsestr(response.text)


def handle_pull_request(data):
    """ Handle a pull_request event.

        This event is triggered when a pull request is assigned, unassigned,
        labeled, unlabeled, opened, closed, reopened, or synchronized.

        https://developer.github.com/v3/activity/events/types/#pullrequestevent
    """

    # Pull requests form the base of the email threads used in this webook.
    # Any time a request is opened or synchronized (push --force on the branch
    # to be pulled), start a new email thread using the pull request body as
    # the cover letter, and reply to it with each of the patches.

    pull_request = data["pull_request"]

    # Construct the message ID for the cover letter that we will either be
    # sending or replying to
    cover_msg_id = pull_request_msg_id(data["pull_request"])

    if data["action"] in ("opened", "synchronize"):
        if data["action"] == "opened":
            subject = "New: "
        else:
            subject = "Updated: "

        subject += "[%s/pulls/%s %s] %s" % \
                (pull_request["base"]["repo"]["full_name"], data["number"],
                        pull_request["base"]["ref"], pull_request["title"])

        from_addr = "%s <%s>" % (data["sender"]["login"], os.environ["GHEH_EMAIL_FROM"])

        body = pull_request["body"] + email_footer(pull_request["html_url"])

        cover_letter = MIMEText(body)
        cover_letter['From'] = from_addr
        cover_letter['Subject'] = subject
        cover_letter['Message-Id'] = cover_msg_id
        cover_letter['Date'] = json_to_email_date(pull_request['updated_at'])
        send_email(cover_letter)

        # Get a list of commits in this pull request
        commit_list = get_github(pull_request["url"] + "/commits").json()
        patch_num = 1
        tot_num = len(commit_list)

        for commit in commit_list:
            # Start with the .patch file provided by github since it's
            # formatted all nice and email-like
            msg = read_message(commit['html_url'] + '.patch')

            # Set the message as a reply to the cover letter
            msg['In-Reply-To'] = cover_msg_id

            msg['Message-Id'] = patch_msg_id(pull_request, commit["sha"])

            # Reset the Date header so that patches aren't coming from a time
            # before the message they're supposed to be replying to.
            # git-send-email does something similar, so everyone seems pretty
            # ok with this, as a concept.
            del msg['Date']
            msg['Date'] = json_to_email_date(pull_request['updated_at'])

            # Prepend a From: to the body of the message so git-am works right.
            # Add the footer.
            msg.set_payload('From: %s\n\n%s\n%s' % \
                    (msg['From'], msg.get_payload(),
                        email_footer(commit['html_url'], msg_type='commit')))

            # Replace the From header with ourselves
            del msg['From']
            msg['From'] = from_addr

            # Reset the Content-Transfer-Encoding so that non-ascii characters
            # get encoded right. This will encode the payload as base64.
            del msg['Content-Transfer-Encoding']
            msg.set_charset('utf-8')

            # Monkey with the subject to get the patch numbers and branch name in there
            subject = msg['Subject'].replace('[PATCH]',
                    '[%s %d/%d]' % (pull_request["base"]["ref"], patch_num, tot_num), 1)
            del msg['Subject']
            msg['Subject'] = subject
            send_email(msg)

            patch_num += 1

        # Create (or update) a database record with the pull request and
        # the list of commits
        client = pymongo.MongoClient(os.environ[os.environ["GHEH_DB_ENVVAR"]])
        db = client[os.environ['GHEH_DB_NAME']]
        pull_request_coll = db[PULL_REQUEST_COLLECTION]

        record = pull_request_coll.find_one({'pull_request.id': pull_request['id']})
        if record:
            record['pull_request'] = pull_request
            record['commit_list'] = commit_list
            pull_request_coll.save(record)
        else:
            pull_request_coll.insert({'pull_request': pull_request, 'commit_list': commit_list})

    elif data["action"] in ("closed", "reopened", "assigned", "unassigned"):
        if data["action"] == "assigned":
            subject = "User %s has assigned %s/pulls/%s to %s" % \
                    (data["sender"]["login"],
                     pull_request["base"]["repo"]["full_name"], data["number"],
                     data["assignee"]["login"])
        else:
            subject = "User %s has %s %s/pulls/%s" % \
                    (data["sender"]["login"], data["action"],
                     pull_request["base"]["repo"]["full_name"], data["number"])

        from_addr = "%s <%s>" % (data["sender"]["login"], os.environ["GHEH_EMAIL_FROM"])

        msg = MIMEText(email_footer(pull_request["html_url"]))
        msg["From"] = from_addr
        msg["Subject"] = subject
        msg["In-Reply-To"] = cover_msg_id
        msg["Date"] = json_to_email_date(pull_request["updated_at"])
        send_email(msg)

def handle_issue_comment(data):
    """ Handle a issue_comment event.

        This event is triggered any time a pull request or issue is commented
        on.
    """

    # We're only interested in pull request comments for now
    if "pull_request" not in data["issue"]:
        return

    # TODO: Might need to do something different for different "action" values
    # if different action values are ever implemented

    # TODO message-id

    # Figure out what email this will be a reply to
    pull_request = get_github(data["issue"]["pull_request"]["url"]).json()
    cover_msg_id = pull_request_msg_id(pull_request)

    subject = "User %s commented on %s/pulls/%s" % \
            (data["comment"]["user"]["login"],
             data["repository"]["full_name"],
             pull_request["number"])

    from_addr = "%s <%s>" % (data["comment"]["user"]["login"], os.environ["GHEH_EMAIL_FROM"])

    body = data["comment"]["body"] + email_footer(data["issue"]["html_url"])

    msg = MIMEText(body)
    msg['From'] = from_addr
    msg['Subject'] = subject
    msg['In-Reply-To'] = cover_msg_id
    msg['Date'] = json_to_email_date(data["issue"]["updated_at"])
    send_email(msg)

def handle_pull_request_review_comment(data):
    """ Handle a pull request review comment.

        This event is triggered by comments left on the unified diff (both
        split and unified views) for a pull request, via the "Files changed"
        tab.
    """

    # TODO: same as issue comments, might need to do something with "action" if
    # action ever gets used

    # TODO Message-Id

    cover_msg_id = pull_request_msg_id(data["pull_request"])
    
    subject = "User %s commented on the diff for %s/pulls/%s" % \
            (data["comment"]["user"]["login"],
             data["repository"]["full_name"],
             data["pull_request"]["number"])

    from_addr = "%s <%s>" % (data["comment"]["user"]["login"], os.environ["GHEH_EMAIL_FROM"])

    # Start with the diff being commented on as a quote
    body = '\n'.join('> ' + line for line in data["comment"]["diff_hunk"].split('\n'))
    body += '\n\n' + data["comment"]["body"]
    body += '\n' + email_footer(data["comment"]["html_url"])

    msg = MIMEText(body)
    msg['From'] = from_addr
    msg['Subject'] = subject
    msg['In-Reply-To'] = cover_msg_id
    msg['Date'] = json_to_email_date(data["comment"]["updated_at"])
    send_email(msg)


# Service, serve thyself
# This is only needed for running outside of mod_wsgi
if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    try:
        httpd = make_server('', os.environ.get('GHEH_HTTP_PORT', 8080), application)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Exiting on user interrupt")
