#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Summarise Pyzor database.

Generate a summary of the current state of a Pyzor database.

This currently only works with a MySQL (or compatible) database.
This can currently only output to a Slack channel.

There are extra requirements for this script:

 * click
 * requests
"""

import os
import datetime
import ConfigParser

import MySQLdb

import requests

import click


@click.command()
@click.option("--config", default=None)
@click.argument("hook")
def summarise(config, hook):
    """Generate a summary of a Pyzor database."""
    if config is None:
        config = os.path.expanduser("~/.pyzor/config")
    conf = ConfigParser.ConfigParser()
    conf.read(config)
    (host, user, password, db_name,
     table) = conf.get("server", "DigestDB").split(",")
    db = MySQLdb.connect(
        host=host,
        user=user,
        db=db_name,
        passwd=password,
        )
    c = db.cursor()
    
    # TODO: With a newer Python, this could use f-strings.
    data = {}
    c.execute(
        "SELECT COUNT(*) FROM `%s`" % table
        )
    data["total"] = c.fetchone()[0]
    c.execute(
        "SELECT MIN(wl_entered), MIN(wl_updated), "
        "MIN(r_entered), MIN(r_updated), MAX(wl_entered), MAX(wl_updated), "
        "MAX(r_entered), MAX(r_updated) from `%s`" % table
        )
    (data["oldest_white"], data["oldest_white_update"],
     data["oldest_spam"], data["oldest_spam_update"],
     data["newest_white"], data["newest_white_update"],
     data["newest_spam"], data["newest_spam_update"]
     ) = c.fetchone()
    c.execute(
        "SELECT MAX(r_count), MAX(wl_count) FROM `%s`" % table
        )
    data["max_spam"], data["max_white"] = c.fetchone()

    # Frequency table for counts.
    for column in ("r_count", "wl_count"):
        buckets = []
        for bucket in range(10):
            low = bucket * 100
            high = (bucket + 1) * 100
            c.execute(
                "SELECT COUNT(*) FROM `%s` WHERE %s BETWEEN %%s AND %%s" %
                (table, column), (low, high)
                )
            buckets.append(c.fetchone()[0])
        data[column] = buckets

    # Frequency table for age.
    for column in ("r_updated", "wl_updated"):
        buckets = []
        for bucket in range(10):
            low = datetime.datetime.now() - datetime.timedelta(days=(bucket + 1) * 7)
            high = datetime.datetime.now() - datetime.timedelta(days=bucket * 7)
            c.execute(
                "SELECT COUNT(*) FROM `%s` WHERE %s BETWEEN %%s AND %%s" %
                (table, column), (low, high)
                )
            buckets.append(c.fetchone()[0])
        data[column] = buckets

    data["table"] = table
    notify_slack(hook, data)

    c.close()
    db.close()


TEXT = u"""Pyzor summary for _%(table)s_:

• There are %(total)s digests; the most common spam digest has %(max_spam)s reports, and the most common whitelisted digest has %(max_white)s whitelists.

• The oldest spam digest is from %(oldest_spam)s, and the oldest update is from %(oldest_spam_update)s.
• The oldest whitelisted digest is from %(oldest_white)s, and the oldest update is from %(oldest_white_update)s.

• The latest spam digest is from %(newest_spam)s, and the latest update is from %(newest_spam_update)s.
• The latest whitelisted digest is from %(newest_white)s, and the latest update is from %(newest_white_update)s.
"""

ticks = u" ▁▂▃▄▅▆▇█"


# Borrowed from https://raw.githubusercontent.com/kennethreitz/spark.py/master/spark.py
def spark_string(ints, fit_min=False):
    """Returns a spark string from given iterable of ints.
    
    Keyword Arguments:
    fit_min: Matches the range of the sparkline to the input integers
             rather than the default of zero. Useful for large numbers with
             relatively small differences between the positions
    """
    min_range = min(ints) if fit_min else 0
    step_range = max(ints) - min_range
    step = (step_range / float(len(ticks) - 1)) or 1
    return u''.join(ticks[int(round((i - min_range) / step))] for i in ints)


def notify_slack(hook, data):
    """Send a notification containing a summary of a Pyzor database to a Slack channel."""
    text = TEXT % data
    attachments = [
        {
            "title": "Spam Reports",
            "text": spark_string(data["r_count"], fit_min=True),
        },
        {
            "title": "Whitelist Reports",
            "text": spark_string(data["wl_count"], fit_min=True),
        },
        {
            "title": "Spam Age",
            "text": spark_string(data["r_updated"], fit_min=True),
        },
        {
            "title": "Whitelist Age",
            "text": spark_string(data["wl_updated"], fit_min=True),
        },
    ]
    response = requests.post(
        hook,
        json={"text": text, "attachments": attachments}
        )


if __name__ == "__main__":
    summarise()
