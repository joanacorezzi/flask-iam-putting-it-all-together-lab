from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    # columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationship: a user has many recipes
    recipes = db.relationship('Recipe', back_populates='user')

    # do not allow reading password_hash directly
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    # allow setting password_hash, but store it encrypted with bcrypt
    @password_hash.setter
    def password_hash(self, password):
        # bcrypt returns bytes, so we decode to a normal string
        hashed_password = bcrypt.generate_password_hash(
            password.encode('utf-8')
        ).decode('utf-8')

        self._password_hash = hashed_password

    # logging in check password
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash,
            password.encode('utf-8')
        )

    # validations
    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == '':
            raise ValueError("Username must be present.")
        return username


class Recipe(db.Model):
    __tablename__ = 'recipes'
    
    # columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # foreign key + relationship (recipe belongs to a user)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='recipes')

    # validations
    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == '':
            raise ValueError("Title must be present.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or instructions.strip() == '':
            raise ValueError("Instructions must be present.")
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions


class UserSchema(Schema):
    # return to the frontend (no password)
    id = fields.Int()
    username = fields.Str()
    image_url = fields.Str()
    bio = fields.Str()


class RecipeSchema(Schema):
    id = fields.Int()
    title = fields.Str()
    instructions = fields.Str()
    minutes_to_complete = fields.Int()

    # nested user object
    user = fields.Nested(UserSchema)
