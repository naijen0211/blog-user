from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
from functools import wraps
from hashlib import md5


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


Base = declarative_base()
##CONFIGURE TABLES

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user_data.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")




class User(db.Model, UserMixin, Base):
    __tablename__ = "user_data"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments_data"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user_data.id'))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    #date = db.Column(db.String(250), nullable=False)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


def admin_only(func):
    @wraps(func)
    def wrapped_function():
        if current_user.get_id() is not None:
            return func()
        return abort(403)
    return wrapped_function



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    #print(posts)
    #print(current_user.get_id())
    return render_template("index.html", all_posts=posts, login=current_user.is_authenticated, id=current_user.get_id())


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first() is None:
            new_user = User(name=form.name.data.lower(), email=form.email.data, password= generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            #flash("You are in!!")
            login_user(new_user)
            return redirect(url_for("get_all_posts", login=current_user.is_authenticated))
        else:
            flash("You have registered before!")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("get_all_posts", login=current_user.is_authenticated))
            flash("You got the wrong password.")
            return render_template("login.html", form=form)
        flash("You should register first.")
        return redirect(url_for("register"))
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    commentform = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comment = Comment.query.all()
    if commentform.validate_on_submit():
        print(current_user.is_authenticated)
        if current_user.is_authenticated:
            new_comment = Comment(author=current_user, text=commentform.comment.data)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        flash("You need to login to leave a comment.")
        return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, gravatar=gravatar, login=current_user.is_authenticated, comments=comment, commentform=commentform, id=current_user.get_id())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, login=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,  login=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
