

from functools import wraps
from sqlalchemy.sql import func
from . import app,db
from flask import jsonify, request,make_response

from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from datetime import datetime,timedelta
from flask import jsonify
from .models import ConseillerLocal, db, AdminPublique, President, ProgrammeVisite

from flask import request, jsonify



# -------------------------------------------------------------------------------------------------------------



# -------------------------------------------------------------------------------------------------------------


@app.route('/api/conseillers-emails', methods=['GET'])
def get_conseillers_emails():
    # Récupérer les emails des conseillers locaux depuis la base de données
    conseillers = ConseillerLocal.query.all()
    emails = [conseiller.email for conseiller in conseillers]
    return jsonify(emails)

@app.route('/api/admins-emails', methods=['GET'])
def get_admins_emails():
    # Récupérer les emails des administrateurs publics depuis la base de données
    admins = AdminPublique.query.all()
    emails = [admin.email for admin in admins]
    return jsonify(emails)








# -------------------------------------------------------------------------------------------------------------------


@app.route('/api/conseillers', methods=['GET'])
def get_conseillers():
    # Récupérer la liste des conseillers locaux depuis la base de données
    conseillers = ConseillerLocal.query.all()
    conseillers_data = [{'id': conseiller.id, 'email': conseiller.email} for conseiller in conseillers]
    return jsonify(conseillers_data)

@app.route('/api/admins', methods=['GET'])
def get_admins():
    # Récupérer la liste des administrateurs publics depuis la base de données
    admins = AdminPublique.query.all()
    admins_data = [{'id': admin.id, 'email': admin.email} for admin in admins]
    return jsonify(admins_data)



# -----------------------------------------------------------------------------------------------------------------------





@app.route("/login",methods=["POST"])
def login():
    auth=request.json
    print("Auth reçu :", auth)
    if not auth or not auth.get("email") or not auth.get("password"):
        print("Informations d'identification manquantes")
        return make_response(
            jsonify({"message": "Proper credentials were not provided"}), 401
        )
    President = President.query.filter_by(email=auth.get("email")).first()
    if not President:
        print("Utilisateur non trouvé")
        return make_response(
            jsonify({"message": "Please create an account"}), 401
        ) 
    if check_password_hash(President.password,auth.get('password')):
        token = jwt.encode({
            'id':President.id,
            'exp':datetime.utcnow() + timedelta(minutes=30)
        },
        "secret",
        "HS256"
        )
        print("Token généré :", token)
        return make_response(jsonify({'token':token}), 201)
    print("Informations d'identification incorrectes")
    return make_response(
        jsonify({'message': 'Please check your credentials'}), 401
    )



def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'Authorization' in request.headers:
            token = request.headers["Authorization"]
        if not token:
            return make_response({"message":"Token is missing "},401)
        
        try:
            data=jwt.decode(token,"secret",algorithms=["HS256"])
            current_President = President.query.filter_by(id=data["id"]).first()
            print(current_President)
        except Exception as e :
            print(e)
            return make_response({
            "message":"token is invalid"},401)
        return f(current_President, *args,**kwargs)
    return decorated





if __name__ == '__main__':
    app.run(debug=True)
