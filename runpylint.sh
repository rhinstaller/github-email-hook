#!/bin/sh

# W0511: Used when a warning note as FIXME or XXX is detected
python3-pylint -r n --disable=C,R --rcfile=/dev/null \
    --dummy-variables-rgx=_ \
    --disable=W0511 \
    wsgi.py cronjob.py github_email_hook/*.py
