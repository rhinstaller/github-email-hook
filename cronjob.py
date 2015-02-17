#!/usr/bin/env python
#
# github to email bridge, cron job part
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

# Run this script periodically to find comments on commits in a pull request,
# when the comments on made on the repository being pulled from (i.e., the
# repo that we don't control)

import sys
import os
import time
import pymongo

from github_email_hook import get_github, handle_commit_comment
from github_email_hook.constants import DB_NAME, PULL_REQUEST_COLLECTION
from github_email_hook.constants import COMMIT_COMMENT_COLLECTION, COMMENT_SENT_COLLECTION

if __name__ == '__main__':
    client = pymongo.MongoClient(os.environ[os.environ["GHEH_DB_ENVVAR"]])
    db = client[DB_NAME]
    pull_request_coll = db[PULL_REQUEST_COLLECTION]
    commit_comment_coll = db[COMMIT_COMMENT_COLLECTION]
    comment_sent_coll = db[COMMENT_SENT_COLLECTION]

    # First, iterate over all the pull requests
    for pull_request in pull_request_coll.find():
        # Second, all the commits in the pull request
        for commit in pull_request['commit_list']:
            # Construct the API url for the comment list on the commit in the source repo
            comment_list_url = "%s/commits/%s/comments" % \
                    (pull_request['pull_request']['head']['repo']['url'], commit['sha'])
            
            # Check if we have a etag stored from a previous run
            record = commit_comment_coll.find_one({'comment_list_url': comment_list_url})
            if record:
                etag = record['etag']
            else:
                etag = None

            # Fetch the comment list
            comment_list_response = get_github(comment_list_url, etag)

            # If we got a 304, there are no new comments, so we're done with this commit
            if comment_list_response.status_code == 304:
                continue

            # Hopefully the status code is 200 otherwise, but if not bail on this commit
            if comment_list_response.status_code != 200:
                print("ERR: Received status code %s from github for %s" %
                        (comment_list_response.status_code, comment_list_url), file=sys.stderr)
                continue

            comment_list = comment_list_response.json()

            # Iterate over the comments and look for the ones not yet emailed
            for comment in comment_list:
                if not comment_sent_coll.find_one({'comment.url': comment["url"]}):
                    # Fake a commit_comment event
                    handle_commit_comment({'comment': comment})
                    comment_sent_coll.insert({'comment': comment, 'last_sent': time.time()})

            # Insert or update the comment list record
            if record:
                record['etag'] = comment_list_response.headers['etag']
                record['comment_list'] = comment_list
                commit_comment_coll.save(record)
            else:
                commit_comment_coll.insert({'comment_list_url': comment_list_url,
                    'etag': comment_list_response.headers['etag'],
                    'comment_list': comment_list})
