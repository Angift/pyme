import os, getpass
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from models import db, User, Visit
from functions import allowed_file

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ALLOWED_EXTENSIONS_IMAGES = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg'}

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'maxatlastuchman@gmail.com'
app.config['MAIL_PASSWORD'] = 'Atl4stotaj'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static')
jwt = JWTManager(app)

db.init_app(app)
Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)
manager = Manager(app)
manager.add_command("db", MigrateCommand)

CORS(app)

# Using the expired_token_loader decorator, we will now call
# this function whenever an expired but otherwise valid access
# token attempts to access an endpoint
@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'The {} token has expired'.format(token_type)
    }), 401

@app.route('/')
def main():
    return render_template('index.htm')

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON request"}), 400
    
    email = request.json.get('email', None)
    password = request.json.get('password', None) 

    if not email or email == '':
        return jsonify({"msg":"Missing email request"}), 400
    if not password or password == '':
        return jsonify({"msg":"Missing password request"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "email/password incorrecto"}), 401

    if bcrypt.check_password_hash(user.password, password):        
        access_token = create_access_token(identity=user.email)
        data = {
            "access_token": access_token,
            "user": user.serialize()
        }
        return jsonify(data), 200
    return jsonify({"msg": "email/password incorrectos"}), 401


@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON request"}), 400
    
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    direccion = request.json.get('direccion', '')
    fantasyname = request.json.get('fantasyname', '')
    rubro = request.json.get('rubro', '')
    empleados = request.json.get('empleados', '')
    ingresos = request.json.get('ingresos', '')

    if not email or email == '':
        return jsonify({"msg":"Missing email request"}), 400
    if not password or password == '':
        return jsonify({"msg":"Missing password request"}), 400
    
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"msg": "email exist"}), 400

    user = User()
    user.email = email
    user.password = bcrypt.generate_password_hash(password)
    user.direccion = direccion
    user.fantasyname = fantasyname
    user.rubro = rubro
    user.empleados = empleados
    user.ingresos = ingresos

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.email)
    data = {
        "access_token": access_token,
        "user": user.serialize()
    }

    return jsonify(data), 201

@app.route('/change-password', methods=['POST'])
@jwt_required
def changepassword():
    if not request.is_json:
        return jsonify({"msg":"Missing JSON request"}), 400

    oldpassword = request.json.get('oldpassword', None)
    password = request.json.get('password', None)

    if not oldpassword or oldpassword == '':
        return jsonify({"msg":"Missing oldpassword request"}), 400
    if not password or password == '':
        return jsonify({"msg":"Missing password request"}), 400

    email = get_jwt_identity()

    user = User.query.filter_by(email=email).first()

    if bcrypt.check_password_hash(user.password, oldpassword):        
        user.password = bcrypt.generate_password_hash(password)
        db.session.commit()        
        return jsonify({"success": "password has change"}), 200
    else:
        return jsonify({"msg": "oldpassword is incorrect"}), 400

@app.route('/users', methods=['GET', 'POST'])
@app.route('/users/<int:id>', methods=['GET','PUT','DELETE'])
@jwt_required
def users(id = None):
    if request.method == 'GET':
        return jsonify({"msg":"users GET"}), 200
    if request.method == 'POST':
        return jsonify({"msg":"users POST"}), 200
    if request.method == 'PUT':
        return jsonify({"msg":"users PUT"}), 200
    if request.method == 'DELETE':
        return jsonify({"msg":"users DELETE"}), 200

@app.route('/contact', methods=['POST'])
def contact():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON request"}), 400
    
    name = request.json.get('name', None)
    email = request.json.get('email', None)
    message = request.json.get('message', '')
    

    if not name or name == '':
        return jsonify({"msg":"Missing name request"}), 400
    if not email or email == '':
        return jsonify({"msg":"Missing email request"}), 400
    if not message or message == '':
        return jsonify({"msg":"Missing message request"}), 400
    
    data = {
        "name": name,
        "email": email,
        "message": message
    }

    msg = Message("Web Contact", sender="maxatlastuchman@gmail.com", recipients=["maxatlastuchman@gmail.com"])
    msg.html = render_template('email_template.htm', data=data)
    mail.send(msg)

    return jsonify({"success": "Email enviado"}), 200

@app.route('/scorecard', methods=['POST'])
def scorecard():

    id = request.form.get('id', None)    

    user = User.query.get(id)
   

    file = request.files['file']
    if file and file.filename != '' and allowed_file(file.filename, ALLOWED_EXTENSIONS_IMAGES):
        filename = secure_filename(file.filename)
        file.save(os.path.join(os.path.join(app.config['UPLOAD_FOLDER'], 'img/files'), filename))             
    else:  
        return jsonify({"msg": "File not allowed"}), 400                     
    
    
    if file:
        user.file = filename
    
    db.session.commit()

    return jsonify(user.serialize()), 200 

@app.route('/users/file/<filename>')
def file(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'img/files'), filename)

@app.route("/counter", methods=['GET'])
def count():
    
    v = Visit.query.first()
    if not v:
        v = Visit()
        v.count += 1
        db.session.add(v)
    v.count +=1
    db.session.commit()
    return jsonify(counter=v.count)
    
if __name__ == '__main__':
    manager.run()