#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

# schemas used to turn model objects into dictionaries 
user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)


class Signup(Resource):
     def post(self):
        # request json
        data = request.get_json()

        try:
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )

            # hash + store password
            user.password_hash = data.get('password')

            db.session.add(user)
            db.session.commit()

            # save user id in session (auto-login)
            session['user_id'] = user.id

            return user_schema.dump(user), 201

        except (ValueError, IntegrityError):
            db.session.rollback()
            return {"errors": ["Validation errors"]}, 422



class CheckSession(Resource):
    def get(self):
        # if user_id is in session, they are logged in
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)

            # if found the user, return their data
            if user:
                return user_schema.dump(user), 200

        # if not logged in, return an error
        return {"error": "Unauthorized"}, 401

class Login(Resource):
     def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        # find user by username
        user = User.query.filter(User.username == username).first()

        # if user not found = 401
        if user is None:
            return {"error": "Unauthorized"}, 401

        # if password wrong = 401
        if not user.authenticate(password):
            return {"error": "Unauthorized"}, 401

        # success = store session and return user
        session['user_id'] = user.id
        return user_schema.dump(user), 200
class Logout(Resource):
    def delete(self):
        # if logged in, remove user_id from session
        if session.get('user_id'):
            session.pop('user_id', None)
            return {}, 204

        # if not logged in
        return {"error": "Unauthorized"}, 401

class RecipeIndex(Resource):
    def get(self):
        # must be logged in
        if not session.get('user_id'):
            return {"error": "Unauthorized"}, 401

        # get all recipes
        recipes = Recipe.query.all()

        # return list of recipes (each includes nested user)
        return recipes_schema.dump(recipes), 200

    def post(self):
        # must be logged in
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()

        try:
            # make recipe that belongs to the logged-in user
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe_schema.dump(recipe), 201

        except ValueError as e:
            # model validations raise ValueError
            db.session.rollback()
            return {"errors": [str(e)]}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)