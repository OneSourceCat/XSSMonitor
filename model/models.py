#!/usr/bin/env python
# -*- coding: utf-8 -*-
from db import *
import datetime

class BaseModel(Model):
    class Meta:
        database = database

class User(BaseModel):
    '''
    用户列表
    '''
    username = CharField()
    password = CharField()

class Projects(BaseModel):
    project_name = CharField()
    white_list = TextField()
    alert_count = IntegerField(default=0)
    create_time = DateTimeField(default=datetime.datetime.now)

class AlertRecords(BaseModel):
    project_name = ForeignKeyField(Projects, related_name='project')
    alert_type = CharField()
    attack_stack = CharField()
    alert_time = DateTimeField(default=datetime.datetime.now)
    source = CharField()


