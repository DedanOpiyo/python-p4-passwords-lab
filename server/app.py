#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

class CheckSession(Resource):
    
    def get(self):

        user_id = session.get('user_id')
        if user_id:
            try:
                user = User.query.filter(
                    User.id == user_id
                ).first()

                return user.to_dict(), 200
            except:
                return jsonify({'message': 'Something went wrong. Please try again.'}), 500
        else:
            return {}, 204 # Status code

class Login(Resource):
    
    def post(self):
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Login credentials missing"}), 401
        
        try:
            user = User.query.filter(User.username == data['username']).first()

            password = data.get('password')
        
            if user.authenticate(password):
                
                session['user_id'] = session.get('user_id') or user.id
                
                return user.to_dict(), 200
            
        except:
            return jsonify({'error': 'Invalid username or password'}), 401 # Or {'error': '401 Unauthorized'}

class Logout(Resource):
    
    def delete(self):
        
        session['user_id'] = None
        
        return {}, 204 # {'message': '204: No Content'}

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='ckeck_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
