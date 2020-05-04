from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    direccion = db.Column(db.String(100), nullable=True)
    fantasyname = db.Column(db.String(100), nullable=True)
    rubro = db.Column(db.String(100), nullable=True)
    empleados = db.Column(db.String(100), nullable=True)
    ingresos = db.Column(db.String(100), nullable=True)
    file = db.Column(db.String(400), nullable=True, default='files.png')

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "direccion": self.direccion,
            "fantasyname": self.fantasyname,
            "rubro": self.rubro,
            "empleados": self.empleados,
            "ingresos": self.ingresos,
            "file": self.file
        }

class Visit(db.Model):    
    id = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer)

    def __init__(self):
        self.count = 0