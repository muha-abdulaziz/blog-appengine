import os
import webapp2
import jinja2
import re

import hmac
import random
import string
import hashlib

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Handler(webapp2.RequestHandler):
    '''Enclued some procedules to Handel the requests'''

    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#####################################################################
######################### Data base schema ##########################
#####################################################################
class Posts(db.Model):
    '''there is 3 entites:
    subject ----> String
    content ----> Text
    created ----> DateTime
    '''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class UserInfo(db.Model):
    '''there is 3 entites:
    username ----> String
    password ----> String
    email    ----> String
    '''
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

#####################################################################
####################### Managing the blog ###########################
#####################################################################
class MainPage(Handler):
    def front_render(self):
        posts = db.GqlQuery("SELECT * FROM Posts ORDER BY created DESC limit 10")
        self.render("frontPage.html", posts=posts)

    def get(self):
        self.front_render()


class NewPost(Handler):
    def npost_render(self, subject="", content="", error=""):
        self.render("newPost.html", subject=subject, content=content, error=error)
    
    def get(self):     
        self.npost_render()
    
    def post(self):
        user_subject = self.request.get("subject")
        user_content = self.request.get("content")

        if user_content and user_subject:
            add_post = Posts(subject=user_subject, content=user_content)
            add_post.put()
            
            new_posd_id = add_post.key().id()
            self.redirect("/blog/{0}".format(new_posd_id))
            # self.redirect("/blog")
        else:
            error = "The title and the subject both are required"
            self.npost_render(user_subject, user_content, error)

class SinglePost(Handler):
    def single_post_render(self, subject="", content=""):
        self.render("singlePost.html", subject=subject, content=content)
    
    def get(self, post_id):
        post_key = db.Key.from_path('Posts', int(post_id))
        post = db.get(post_key)

        if not post:
            self.error(404)
            return
        
        self.single_post_render(post.subject, post.content)

#####################################################################
####################### sign up, in and out #########################
#####################################################################

SECRET = 'imsosecret'


def hash_str(s):
    '''It take a string and returns it's hmac hash'''
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    '''It take a string and returns a string, hash pair
    input   -->  string
    output  -->  "s|hash"
    '''
    return "%s|%s" % (s, hash_str(s))
def cookie_split(cookie):
    return cookie.split("|")

def check_secure_val(h):
    '''It takes a string, hash pair, check
    and if it's correct return the string
    input   --> "string,hash"
    output  --> string
    '''
    cookie = cookie_split(h)
    if hash_str(cookie[0]) == cookie[1]:
        return cookie[0]

#####################################################################
########################## For password #############################
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    comma = h.find(",")
    salt = h[comma+1:]
    del comma
    return h == make_pw_hash(name, pw, salt)

#####################################################################
##################### validating the form inputs ####################

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$" )

def valid_username(username):
    return USER_RE.match(username)

def valid_email(email):
    return EMAIL_RE.match(email)

def valid_passwd(passwd):
    return PASWORD_RE.match(passwd)
######################################################################
########################### SignUp page ##############################
class SignUp(Handler):
    '''Handling the sign up page'''
    def render_signup(self, username="",user_error="",\
    pw_error="", verify_error="", email="",email_error=""):
    
        self.render("signUp.html",\
        username=username, username_error=user_error,\
        pw_error=pw_error, verify_error=verify_error,\
        email=email, email_error=email_error)

    
    def get(self):
        self.render_signup()
    
    def post(self):
        # get what user entered
        i_username = self.request.get("username")
        i_pw = self.request.get("password")
        i_verify = self.request.get("verify")
        i_email = self.request.get("email")

        # Validating what user entered
        v_username = valid_username(i_username)
        v_pw = valid_passwd(i_pw)

        def success(email=None):
            '''automated job when the signup is success'''
            pw_hash = make_pw_hash(i_username, i_pw)
            add_info = UserInfo(username=i_username, password=pw_hash,\
            email=email)
            add_info.put()
            # set a caokie
            user_id = str(add_info.key().id())
            cookie_str = make_secure_val(user_id)
            self.response.headers.add_header('Set-Cookie', 'user_id={0}'.format(cookie_str))
            self.redirect('/blog/welcome')


        if len(i_email) == 0:
            if v_username and v_pw and i_pw == i_verify:
                success()
            else:
                username_error = ""
                pw_error = ""
                verify_error = ""

                if not v_username:
                    username_error = "Enter a valid user name"
                
                if not v_pw:
                    pw_error = "Enter a valid password"
                
                if not i_pw == i_verify:
                    verify_error = "Does not match the password Field"
                
                self.render_signup(i_username, username_error,\
                pw_error, verify_error)
        else:
            # validating the email
            v_email = valid_email(i_email)
            if v_username and v_pw and (i_pw == i_verify) and v_email:
                success(i_email)
            else:
                username_error = ""
                pw_error = ""
                verify_error = ""
                email_error = ""

                if not v_username:
                    username_error = "Enter a valid user name"
                
                if not v_pw:
                    pw_error = "Enter a valid password"
                
                if not i_pw == i_verify:
                    verify_error = "Does not match the password Field"
                
                if not v_email:
                    email_error = "Enter a valid e-mail"

                self.render_signup(i_username, username_error,\
                pw_error, verify_error, i_email, email_error)
######################################################################
########################### SignUp page ##############################
class Login(Handler):
    def render_login(self, username="", error=""):
        self.render("login.html", username=username, error=error)
    
    def get(self):
        self.render_login()
    
    def post(self):
        i_username = self.request.get("username")
        i_pw = self.request.get("pw")

        if i_username:
            query = "SELECT * FROM UserInfo ;".format(i_username)
            find_username = db.GqlQuery(query)
            for username in find_username:
                print find_username
######################################################################
########################### welcome page #############################
class Welcome(Handler):
    def get(self):
        cookie_user_id = self.request.cookies.get('user_id')
        check_cookie = None
        if cookie_user_id:
            check_cookie = check_secure_val(cookie_user_id)
        if check_cookie:
            user_id = cookie_split(cookie_user_id)[0]
            user_key = db.Key.from_path('UserInfo', int(user_id))
            user_info = db.get(user_key)
            self.write("Welcome {0}".format(user_info.username))
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([('/blog/?',MainPage),\
                               ('/blog/newpost', NewPost),\
                               ('/blog/(\d+)', SinglePost),\
                               ('/blog/signup', SignUp),\
                               ('/blog/welcome', Welcome),\
                               ('/blog/login', Login)], debug=True)