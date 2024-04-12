from . import db
from sqlalchemy.sql import func
from . import db
from sqlalchemy.sql import func
class President(db.Model):
    __tablename__ = "President"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile_image = db.Column(db.String(250)) 
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    AdminPublique = db.relationship('AdminPublique', back_populates='President', cascade='all, delete-orphan')
    conseillerLocale = db.relationship('ConseillerLocal', back_populates='President', cascade='all, delete-orphan')
    programmes_visite = db.relationship('ProgrammeVisite', back_populates='President', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<President {self.firstName} {self.id}>'

    def serialize(self):
        return {
            "id": self.id,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "email": self.email,
            "profile_image": self.profile_image,
            "created_at": self.created_at,
        }

class AdminPublique(db.Model):
    __tablename__ = "AdminPublique"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    directeur = db.Column(db.String(200), nullable=False)
    profile_image = db.Column(db.String(250))  
    PresidentId = db.Column(db.Integer, db.ForeignKey("President.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    President = db.relationship('President', back_populates='AdminPublique')

    def serialize(self):
        return {
            'id': self.id,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'email': self.email,
            'directeur': self.directeur,
            'profile_image': self.profile_image,  
            'created_at': self.created_at
        }

class ConseillerLocal(db.Model):
    __tablename__ = "ConseillerLocal"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile_image = db.Column(db.String(250))  
    PresidentId = db.Column(db.Integer, db.ForeignKey("President.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    President = db.relationship('President', back_populates='conseillerLocale')
    programmes_visite = db.relationship('ProgrammeConseiller', back_populates='conseiller')

    def serialize(self):
        return {
            'id': self.id,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'email': self.email,
            'profile_image': self.profile_image,  
            'created_at': self.created_at
        }

class ProgrammeVisite(db.Model):
    __tablename__ = "ProgrammeVisite"
    id = db.Column(db.Integer, primary_key=True)
    periode_debut = db.Column(db.DateTime(timezone=True), nullable=False)
    periode_fin = db.Column(db.DateTime(timezone=True), nullable=False)
    criteres_evaluation = db.Column(db.String(500), nullable=False)
    lieu = db.Column(db.String(200))  
    description = db.Column(db.Text)   
    contacts_urgence = db.Column(db.String(200))  
    documents_joints = db.Column(db.String(500))  
    PresidentId = db.Column(db.Integer, db.ForeignKey("President.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    President = db.relationship('President', back_populates='programmes_visite')
    conseillers = db.relationship('ProgrammeConseiller', back_populates='programme')

class ProgrammeConseiller(db.Model):
    __tablename__ = 'ProgrammeConseiller'
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'), primary_key=True)
    conseiller_id = db.Column(db.Integer, db.ForeignKey('ConseillerLocal.id'), primary_key=True)
    conseiller = db.relationship("ConseillerLocal", back_populates="programmes_visite")
    programme = db.relationship("ProgrammeVisite", back_populates="conseillers")
    
    
    
    def serialize(self):
        return {
            'programme_id': self.programme_id,
            'conseiller_id': self.conseiller_id
            # Ajoutez d'autres champs si nécessaire
        }