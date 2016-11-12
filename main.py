# Importing all the libraries
import hashlib
import hmac
import os
import re
import database
import jinja2
import webapp2

# Configuring the path for jinja2 template
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = '5d1d7b0e6585678253effe85163aa7ef'

# Hashing password


def hash_password(password, username):
    return hashlib.sha256(password + username + secret).hexdigest()

# Making secure password digest


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Form Validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Main handler


class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def error(self):
        self.render('error.html')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and database.User.get_user_by_id(uid)


class MainPage(MainHandler):
    def get(self):
        posts = database.Post.query()
        self.render('index.html', posts=posts)

# Account Page


class AccountPage(MainHandler):
    def get(self):
        self.render('account.html')

# Login Page


class LoginPage(MainHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        name = self.request.get('username')
        password = self.request.get('password')
        password_hash = hash_password(password, name)
        user = database.User.get_user_by_name_and_password(
            name, password_hash)
        if user:
            self.set_secure_cookie('user_id', str(
                database.User.get_user_id(user)))
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)

# Signup Page


class RegisterPage(MainHandler):
    def get(self):
        self.render('register.html')

    def post(self):
        name = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')

        if valid_username(name):
            if valid_password(password):
                if password == verify:
                    user = database.User.get_user_by_name(name)
                    if user:
                        if user.user_name == name:
                            msg = "The username already exisits."
                            self.render('register.html', error=msg)
                    else:
                        password_hash = hash_password(password, name)
                        user_id = database.User.add_user(name, password_hash)
                        self.set_secure_cookie('user_id', str(user_id))
                        self.redirect('/')
                else:
                    msg = "The passwords do not match."
                    self.render('register.html', error=msg)
            else:
                msg = "That wasn't a valid password."
                self.render('register.html', error=msg)
        else:
            msg = "That's not a valid username."
            self.render('register.html', error=msg)


class LogoutPage(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/')

# Post Page


class PostPage(MainHandler):
    def get(self, post_id):
        post = database.Post.get_post(int(post_id))
        if not post:
            return self.error()
        comments = database.Comment.get_comments_by_post_id(post_id)
        like_text = 'Like'
        if self.user:
            user = self.user
            like = database.LikePost.get_like_by_post_and_author(post_id, user.user_name)
            if like:
                like_text = 'Liked'
        self.render("viewpost.html", post=post, comments=comments, like=like_text)


# Adding PostPage


class AddPostPage(MainHandler):
    def get(self):
        if self.user:
            self.render("addpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        title = self.request.get('title')
        content = self.request.get('content')
        author = user.user_name
        post_id = database.Post.add_post(title=title,
                                         content=content,
                                         author=author)
        self.redirect('/post/' + str(post_id))

# Edit post


class EditPostPage(MainHandler):
    def get(self, post_id):
        post = database.Post.get_post(int(post_id))
        if not post:
            self.error()
            return
        self.render("addpost.html", post=post)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/')

        user = self.user
        title = self.request.get('title')
        content = self.request.get('content')
        # post_id = self.request.get('post_id')
        author = user.user_name
        database.Post.edit_post(title=title,
                                content=content,
                                author=author,
                                post_id=post_id)
        self.redirect('/post/' + str(post_id))

# Delete Post


class DeletePost(MainHandler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('postid')
        post = database.Post.get_post(post_id)

        if post.post_author == user.user_name:
            success = database.Post.delete_post(int(post_id))
            if success:
                self.render('index.html')
                self.redirect('/')
        else:
            self.error(401)
            return

# AddComment


class AddComment(MainHandler):
    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('post_id')
        content = self.request.get('content')
        if post_id and content:
            database.Comment.add_comment(post_id=post_id, text=content, author=user.user_name)
            return self.redirect('/post/' + post_id)
        else:
            return self.error()

# EditComment


class EditComment(MainHandler):
    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('post_id')
        content = self.request.get('content')
        if post_id and content:
            database.Comment.add_comment(post_id=post_id, text=content, author=user.user_name)
            return self.redirect('/post/' + post_id)
        else:
            return self.error()

# DeleteComment


class DeleteComment(MainHandler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        comment_id = self.request.get('comment_id')
        comment = database.Comment.get_comment(comment_id)

        if comment.comment_author == user.user_name:
            success = database.Comment.delete_comment(int(comment_id))
            if success:
                return self.redirect('/')
        else:
            self.error(401)
            return


class AddLike(MainHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post = database.Post.get_post(post_id)
        if not post:
            return self.redirect('/')
        like = database.LikePost.get_like_by_post_and_author(post_id, user.user_name)
        if like:
            database.LikePost.delete_like(like.key.id())
        else:
            if post.post_author == user.user_name:
                return self.redirect('/')
            else:
                database.LikePost.add_like(post_id, user.user_name)

        return self.redirect('/post/' + post_id)

        if post_id and content:
            database.Comment.add_comment(post_id=post_id, text=content, author=user.user_name)
            return self.redirect('/post/' + post_id)
        else:
            return self.error()


class DeleteLike(MainHandler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('postid')
        post = database.Post.get_post(post_id)

        if post.post_author == user.user_name:
            success = database.Post.delete_post(int(post_id))
            if success:
                self.render('index.html')
                self.redirect('/')
        else:
            self.error(401)
            return

# Router


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/account', AccountPage),
    ('/login', LoginPage),
    ('/register', RegisterPage),
    ('/logout', LogoutPage),
    ('/newpost', AddPostPage),
    ('/editpost/([0-9]+)', EditPostPage),
    ('/post/([0-9]+)', PostPage),
    ('/delete', DeletePost),
    ('/addcomment', AddComment),
    ('/editcomment', EditComment),
    ('/deletecomment', DeleteComment),
    ('/addlike/([0-9]+)', AddLike),
    ('/deletelike', DeleteLike),
], debug=True)
