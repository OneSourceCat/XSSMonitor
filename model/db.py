#!/usr/bin/env python
# -*- coding: utf-8 -*-
from peewee import *

database = MySQLDatabase(
    host='127.0.0.1', 
    user='root', 
    passwd='',
    database='xssmonitor',
    charset='utf8'
)
