import os
import random
import jinja2
import webapp2
import re
import logging
import hmac
import hashlib
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'not4u2sea'

def make_secure_val(val):
  return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render(self, template, **kw):
    t = jinja_env.get_template(template)
    self.write(self.render_str(template, **kw))

  def set_secure_cookie(self, name, val):
    self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, make_secure_val(str(val))))

  def initialize(self, *a, **kw):
        self.user = None
        self.blogGroup = BlogGroup.get_or_insert('agroup', name='AGroup')
        webapp2.RequestHandler.initialize(self, *a, **kw)
        cookie = self.request.cookies.get("user_id")
        if (cookie):
            user_id = check_secure_val(cookie)
            if user_id != None:
                self.user = User.get_by_id(int(user_id), parent=None)

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    userId = db.IntegerProperty(required = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty()
    password = db.StringProperty(required = True)

class BlogGroup(db.Model):
    name = db.StringProperty(required = True)

class BlogPage(Handler):
    def get(self):
        if self.user == None :
            self.redirect("/blog/signup")
        else :
            posts = db.GqlQuery("select * from Blog WHERE ANCESTOR IS :1 order by created desc", self.blogGroup)
            logging.warning(self.user.key().id())
            self.render("blog.html", posts = posts, userid = self.user.key().id())

class MainPage(Handler):
    def get(self):
        self.redirect("/blog")

class NewPostPage(Handler):

    def validate(self, subject, content):
        
        if (subject == "" or content == ""):
            return False
        return True;

    def get(self):
        if self.user == None :
            self.redirect("/blog/signup")
        else :  
            self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        userId = self.user.key().id()
        logging.warning(userId)
        if self.validate(subject, content):
            blog = Blog(subject = subject, content = content, userId = userId, parent=self.blogGroup)
            blog.put()
            key = blog.key().id()
            self.redirect("/blog/entry?id=" + str(key))
        else:
            self.render("/newpost.html", subject = subject, content = content, error = "Please enter a subject and content")

class EntryPage(Handler):
    def get(self):
        id = self.request.get("id")
        blog = Blog.get_by_id(int(id), parent=self.blogGroup)
        self.render("entry.html", blog = blog)

class SignupPage(Handler):

    usernameerror = ""
    passworderror = ""
    verifyerror = ""
    emailerror = ""
    username_pattern = re.compile("^[a-zA-Z0-9_-]{3,20}$")
    password_pattern = re.compile("^.{3,20}$")
    email_pattern = re.compile("^[\S]+@[\S]+.[\S]+$")

    def validateForm(self, username, password, verify, email):
        formValid = True
        if self.username_pattern.match(username) == None:
            self.usernameerror = "That's not a valid username"
            formValid = False
        if self.password_pattern.match(password) == None:
            self.passworderror = "That's not a valid password"
            formValid = False
        if password != "" and (verify != password):
            self.verifyerror = "Password's do not match"
            formValid = False
        if email and self.email_pattern.match(email) == None:
            self.emailerror = "That's not a valid email"
            formValid = False
        return formValid

    def isUserNameAvailable(self, username) :
      user = db.GqlQuery("select * from User where username = :1", username)
      if (user.get()):
        logging.warning("User is use")
        self.usernameerror = "That user already exists"
        return False
      else:
        logging.warning("User available")
        return True

    def get(self):
        self.render("/signup.html")

    def post(self):

        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if self.validateForm(username, password, verify, email) and self.isUserNameAvailable(username) :
            password = make_pw_hash(username, password);
            logging.warning(password)
            user = User(username = username, password = password, email = email)
            user.put()
            key = user.key().id()
            self.set_secure_cookie("user_id", key)
            self.redirect("/blog/welcome")
        else :
            self.render("signup.html", password = password, username = username, verify=verify, email=email, usernameerror = self.usernameerror, passworderror = self.passworderror, verifyerror = self.verifyerror, emailerror = self.emailerror)

class WelcomePage(Handler):
    def get(self):
        if self.user == None :
            self.redirect("/blog/signup")
        else :
            self.render("welcome.html", username = self.user.username)

class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def checkPassword(self, username, password):
        # Check to see if the passwords match
        c = db.GqlQuery("select * from User where username = :1", username)
        if (c.get()):
            user = c.get()
            logging.warning(user.password)
            if valid_pw(username, password, user.password):
                self.set_secure_cookie("user_id", user.key().id())
                return True
            else:
                return False
        else:
            return False

    def post(self):
        user_name = self.request.get('username')
        password = self.request.get('password')
        if (self.checkPassword(user_name, password) == False) :
            self.render("login.html", loginerror = "Invalid login")
        else :
            self.redirect("/blog/welcome")
            
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/blog/login")

class DeleteHandler(Handler):
    def get(self):
        user_id = int(self.request.get('id'))
        post = Blog.get_by_id(user_id, parent=self.blogGroup)
        post.delete()
        self.redirect("/blog")

class EditHandler(Handler):
    def get(self):
        post_id = int(self.request.get('id'))
        post = Blog.get_by_id(post_id, parent=self.blogGroup)
        self.render("newpost.html", subject=post.subject, content=post.content)

    def post(self):
        post_id = int(self.request.get('id'))
        post = Blog.get_by_id(post_id, parent=self.blogGroup)
        subject = self.request.get("subject")
        content = self.request.get("content")
        post.subject = subject
        post.content = content
        post.put()
        self.redirect("/blog")

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog', BlogPage),
    ('/blog/newpost', NewPostPage),
    ('/blog/signup', SignupPage),
    ('/blog/welcome', WelcomePage),
    ('/blog/login', LoginPage),
    ('/blog/logout', LogoutHandler),
    ('/blog/delete', DeleteHandler),
    ('/blog/edit', EditHandler),
    ('/blog/entry', EntryPage)
], debug=True)
