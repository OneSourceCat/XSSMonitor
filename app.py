#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division

import os
import sys

import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.escape as escape

from tornado.options import define, options
from model.models import *

define("port", default=8000, help="run on the given port", type=int)
alert_count = 0
p_list = []
info_mappings = {
    'C_SCRIPT': u"创建script元素",
    'C_IFRAME': u"创建iframe元素",
    'C_IMAGE': u"创建image元素",
    'C_Element': u"创建元素",
    'ELE.NAME': u"元素名称",
    'ELE.SRC': u"元素src",
    'IMG.SRC': u"image元素的src",
    'SCRIPT.SRC': u"script元素的src"
}
type_mappings = {
    'C_SCRIPT': u"第三方js",
    'C_IFRAME': u"第三方iframe",
    'C_IMAGE': u"可疑image元素",
    'C_Element': u"可疑元素创建",
}

def get_info(info):
    global info_mappings, type_mappings
    ret_info = ""
    ret_type = ""
    ret_src = ""
    info = info.split("|")
    ret_type = type_mappings[info[0]]
    for i in info:
        tuple_i = i.split('$')
        if len(tuple_i) == 2 and tuple_i[0] in info_mappings.keys():
            k = tuple_i[0]
            source = tuple_i[1]
            ret_src = source
            ret_info += info_mappings[k] + "->"
            ret_info += source + "->"
        elif i in info_mappings.keys():
            ret_info += info_mappings[i] + "->"
        else:
            ret_info += i + "->"
    ret_info = ret_info[:-2]
    return ret_info, ret_type, ret_src



class BaseHandler(tornado.web.RequestHandler):
    '''
    Handler基类
    '''
    def prepare(self):
        global alert_count, p_list
        alert_count = AlertRecords.select().count()
        p_list = Projects.select()

    def get_current_user(self):
        return self.get_secure_cookie("username")

class IndexHandler(BaseHandler):
    '''
    访问首页
    '''
    @tornado.web.authenticated
    def get(self):
        self.redirect('/alert')

class LoginHandler(BaseHandler):
    '''
    登录处理类
    '''
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        user = User.select().where(
            User.username == username).get()
        if user.password == password:
            # 登录成功
            self.set_secure_cookie("username", username)
            self.redirect("/")
        else:
            # 登录失败
            self.render('login.html', 
                error='用户名或密码错误')

class LogoutHandler(BaseHandler):
    '''
    退出登录
    '''
    def get(self):
        self.clear_cookie("username")
        self.redirect("/")

class CreateHandler(BaseHandler):
    def get(self):
        global p_list
        self.render('create.html', 
            p_list=p_list, 
            alert_count=alert_count)

    def post(self):
        """
        创建新项目
        """
        ret = {}
        project_name = self.get_argument('project_name')
        white_list = self.get_argument('white_list')
        try:
            project = Projects(project_name=project_name, 
                white_list=white_list)
            project.save()
            self.write(escape.json_encode({"code":1}))
        except Exception, e:
            self.write(escape.json_encode({"code":0, "error": str(e)}))

class ShowProjectHandler(BaseHandler):
    def get(self):
        self.render("project.html", 
            p_list=p_list,
            projects=p_list,
            alert_count=alert_count)

class DeleteProjectHandler(BaseHandler):
    def post(self):
        pid = self.get_argument('pid')
        try:
            p = Projects.delete().where(Projects.id == pid)
            p.execute()
            self.write(escape.json_encode({"code":1}))
        except Exception, e:
            self.write(escape.json_encode({"code":0, "error":str(e)}))

class DeleteAlertHandler(BaseHandler):
    def post(self):
        aid = self.get_argument('aid')
        try:
            a = AlertRecords.delete().where(AlertRecords.id == aid)
            a.execute()
            self.write(escape.json_encode({"code":1}))
        except Exception, e:
            self.write(escape.json_encode({"code":0, "error":str(e)}))

class ReportHandler(BaseHandler):
    """
    处理告警
    """
    def get(self):
        domain = self.get_argument('d')
        project_name = self.get_argument('p')
        info = self.get_argument('f')
        ctime = self.get_argument('t')
        info, atype, src = get_info(info)
        try:
            # 创建报警
            proj = Projects.select().where(Projects.project_name == project_name).get()
            alert = AlertRecords.create(project_name=proj,
                alert_type=atype, attack_stack=info, source=src)
            alert.save()
            # 项目count + 1
            p = Projects.select().where(Projects.name == project_name).get()
            p.alert_count += 1
            p.save()
        except Exception, e:
            print "[+]ReportHandler Error:" + str(e)


class ShowCodeHandler(BaseHandler):
    def get(self):
        pid = self.get_argument('id')
        query = Projects.get(Projects.id == pid)
        white_list = str(query.white_list.split("\n")).replace("u'", "'")
        project_name = query.project_name
        self.render("code.html", 
            alert_count=alert_count,
            white_list=white_list,
            p_list=p_list,
            project_name=project_name)

class AlertHandler(BaseHandler):
    def get(self):
        alerts = AlertRecords.select()
        self.render("alert.html", alerts=alerts,
            alert_count=alert_count,
            p_list=p_list)

if __name__ == '__main__':
    tornado.options.parse_command_line()
    settings = {
        'debug':True, 
        "cookie_secret":"M7dOsCXdQie9FzZNmGYbZ+9ddbXut0PuvcQT0rQ0qMw=",
        'static_path':os.path.join(os.path.dirname(__file__), 'static'), 
        'template_path':os.path.join(os.path.dirname(__file__), 'templates'),
        'login_url':'/login'
    }
    handlers = [
        (r'/[index]?', IndexHandler),
        (r'/login', LoginHandler), 
        (r'/logout', LogoutHandler),
        (r'/report', ReportHandler),
        (r'/create', CreateHandler),
        (r'/showproject', ShowProjectHandler),
        (r'/del_project', DeleteProjectHandler),
        (r'/show_code', ShowCodeHandler),
        (r'/alert', AlertHandler),
        (r'/del_alert', DeleteAlertHandler),
    ]

    database.create_tables([User, Projects, AlertRecords], True)
    app = tornado.web.Application(handlers=handlers, **settings)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()






