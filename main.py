from flask import Flask, make_response, jsonify, render_template, session
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta
import jwt, os, random
from flask_mail import Mail, Message

from flask import Flask, render_template, Response, jsonify
import gunicorn
from camera import *

app = Flask(__name__)
api = Api(app)        
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/project"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'WhatEverYouWant'
app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
mail = Mail(app)
db = SQLAlchemy(app) 

class Users(db.Model):
    id          = db.Column(db.Integer(), primary_key=True, nullable=False)
    username   = db.Column(db.String(64), nullable=False)
    email       = db.Column(db.String(32), unique=True, nullable=False)
    password    = db.Column(db.String(256), nullable=False)
    verified = db.Column(db.Boolean(1),nullable=False)
    created_at  = db.Column(db.Date)
    updated_at   = db.Column(db.Date)


#Registrasi
regParser = reqparse.RequestParser()
regParser.add_argument('username', type=str, help='Username', location='json', required=True)
regParser.add_argument('email', type=str, help='Email', location='json', required=True)
regParser.add_argument('password', type=str, help='Password', location='json', required=True)
regParser.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/signup')
class Regis(Resource):
    @api.expect(regParser)
    def post(self):
        
        args        = regParser.parse_args()
        username   = args['username']
        email       = args['email']
        password    = args['password']
        rePassword  = args['re_password']
        verified = False
    
        if password != rePassword:
            return {
                'messege': 'Password tidak cocok'
            }, 400

        user = db.session.execute(db.select(Users).filter_by(email=email)).first()
        if user:
            return "Email sudah terpakai silahkan coba lagi menggunakan email lain"
        # END: Check email existance.

        # BEGIN: Insert new user.
        user          = Users() # Instantiate User object.
        user.username = username
        user.email    = email
        user.password = generate_password_hash(password)
        user.verified = verified
        db.session.add(user)
        msg = Message(subject='Verification OTP',sender=os.environ.get("MAIL_USERNAME"),recipients=[user.email])
        token =  random.randrange(10000,99999)
        session['email'] = user.email
        session['token'] = str(token)
        msg.html=render_template(
        'verify_email.html', token=token)
        mail.send(msg)
        db.session.commit()
        # END: Insert new user.
        return {'messege': 'Registrasi Berhasil, Cek email anda untuk verifikasi!'}, 200


#Verifikasi
otpparser = reqparse.RequestParser()
otpparser.add_argument('otp', type=str, help='otp', location='json', required=True)
@api.route('/verifikasi')
class Verifikasi(Resource):
    @api.expect(otpparser)
    def post(self):
        args = otpparser.parse_args()
        otp = args['otp']
        if 'token' in session:
            sesion = session['token']
            if otp == sesion:
                email = session['email']
                user = Users.query.filter_by(email=email).first()
                user.verified = True
                db.session.commit()
                session.pop('token',None)
                return {'message' : 'Email berhasil diverifikasi'}
            else:
                return {'message' : 'Kode Otp tidak sesuai'}
        else:
            return {'message' : 'Kode Otp tidak sesuai'}

#login
logParser = reqparse.RequestParser()
logParser.add_argument('email', type=str, help='Email', location='json', required=True)
logParser.add_argument('password', type=str, help='Password', location='json', required=True)

SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

@api.route('/signin')
class LogIn(Resource):
    @api.expect(logParser)
    def post(self):
        # BEGIN: Get request parameters.
        args        = logParser.parse_args()
        email       = args['email']
        password    = args['password']
        # END: Get request parameters.

        # cek jika kolom email dan password tidak terisi
        if not email or not password:
            return {
                'message': 'Silakan isi email dan kata sandi Anda'
            }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(Users).filter_by(email=email)).first()

        if not user:
            return {
                'message': 'Email atau kata sandi salah'
            }, 400
        else:
            user = user[0] # Unpack the array.
        # END: Check email existance.

        #cek password
        if check_password_hash(user.password, password):
            if user.verified == True:
                token= jwt.encode({
                        "user_id":user.id,
                        "user_email":user.email,
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours= 1)
                },app.config['SECRET_KEY'],algorithm="HS256")
                return {'message' : 'Login Berhasil',
                        'token' : token
                        },200
            else:
                return {'message' : 'Email Belum Diverifikasi ,Silahka verifikasikan terlebih dahulu '},401
        else:
            return {
                'message': 'Email / Password Salah'
            }, 400
        # END: Check password hash.
def decodetoken(jwtToken):
    decode_result = jwt.decode(
               jwtToken,
               app.config['SECRET_KEY'],
               algorithms = ['HS256'],
            )
    return decode_result

authParser = reqparse.RequestParser()
authParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)

@api.route('/user')
class DetailUser(Resource):
       @api.expect(authParser)
       def get(self):
        args = authParser.parse_args()
        bearerAuth  = args['Authorization']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user =  db.session.execute(db.select(Users).filter_by(email=token['user_email'])).first()
            user = user[0]
            data = {
                'username' : user.username,
                'email' : user.email
            }
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401

        return data, 200
#editpassword
editPasswordParser =  reqparse.RequestParser()
editPasswordParser.add_argument('current_password', type=str, help='current_password',location='json', required=True)
editPasswordParser.add_argument('new_password', type=str, help='new_password',location='json', required=True)
@api.route('/editpassword')
class EditPassword(Resource):
    @api.expect(authParser, editPasswordParser)
    def put(self):
        args = editPasswordParser.parse_args()
        argss = authParser.parse_args()
        bearerAuth  = argss['Authorization']
        cu_password = args['current_password']
        newpassword = args['new_password']
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(id=token.get('user_id')).first()
            if check_password_hash(user.password, cu_password):
                user.password = generate_password_hash(newpassword)
                db.session.commit()
            else:
                return {'message' : 'Password Lama Salah'},400
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401
        return {'message' : 'Password Berhasil Diubah'}, 200

#Edit Users
editParser = reqparse.RequestParser()
editParser.add_argument('username', type=str, help='Username', location='json', required=True)
editParser.add_argument('Authorization', type=str, help='Authorization', location='headers', required=True)
@api.route('/edituser')
class EditUser(Resource):
       @api.expect(editParser)
       def put(self):
        args = editParser.parse_args()
        bearerAuth  = args['Authorization']
        username = args['username']
        datenow =  datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        try:
            jwtToken    = bearerAuth[7:]
            token = decodetoken(jwtToken)
            user = Users.query.filter_by(email=token.get('user_email')).first()
            user.username = username
            user.updatedAt = datenow
            db.session.commit()
        except:
            return {
                'message' : 'Token Tidak valid, Silahkan Login Terlebih Dahulu'
            }, 401
        return {'message' : 'Update User Suksess'}, 200

headings = ("Name","Album","Artist")
df1 = music_rec()
df1 = df1.head(15)

@app.route('/deteksi')
def detection():
    print(df1.to_json(orient='records'))
    return render_template('index.html', headings=headings, data=df1)

def gen(camera):
    while True:
        global df1
        frame, df1 = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@app.route('/video_feed')
def video_feed():
    return Response(gen(VideoCamera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/t')
def gen_table():
    return df1.to_json(orient='records')

if __name__ == '__main__':
    app.run(host='192.168.82.136', port=5000, debug=True)

