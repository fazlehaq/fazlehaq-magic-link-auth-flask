import os
from functools import wraps
from dotenv import load_dotenv
from flask import Flask , request , render_template , url_for , make_response , jsonify
from itsdangerous import URLSafeTimedSerializer , BadSignature , SignatureExpired
from mail import send_email
from datetime import timedelta , datetime
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token,jwt_required, get_jwt_identity 
from jwt import ExpiredSignatureError , InvalidTokenError
import jwt

load_dotenv()

blackListedAccesTokens = set()
blackListedRefreshTokens = set()

app = Flask(__name__,template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')


# setting up JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # A strong secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  # Access token lifespan
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)  # Refresh token lifespan
app.config['JWT_TOKEN_LOCATION'] = ['cookies','headers']
# app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh'
jwt_manager = JWTManager(app)


# setting up mailing 
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')


# Serializer to generate tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
def generate_token(email):
    return serializer.dumps(email, salt='email-confirmation-salt')

def isValidToken(token):
    try:
        # Decode the token without verifying its signature (to access the claims)
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], options={"verify_signature": False})
        exp = decoded_token.get('exp')
        if exp:
            # Compare exp with the current time
            return datetime.utcfromtimestamp(exp) > datetime.utcnow()
        return False  # If there's no exp claim, consider it expired
    except jwt.DecodeError:
        return False # If decoding fails, consider it expired
    
def check_blacklist(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers['Authorization'].split()[1]
        
        if token in blackListedAccesTokens:
            return jsonify({"message": "Token is blacklisted."}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


# routes
@app.route('/')
def home():
    return 'Welcome to the Magic Link Authentication System'


@app.route('/login' , methods=['GET','POST'])
def login():
    if request.method == 'GET' :
        return render_template('login.html')
    
    # POST request
    else :
        # get email
        email = request.form['email']

        # check if email exists in user table
            # if not make an entry 
    
        # token generation
        token = generate_token(email)

        # constructing the url 
        magic_link = url_for('confirm_login', token=token, _external=True)

        # sending mail
        send_email(email, 'Login with your magic link', f'Click here to log in: {magic_link}',SENDGRID_API_KEY)
        return "Magic link sent check your email"


@app.route('/confirm_login/<token>')
def confirm_login(token):
    try:
        # Verify the token, max_age is in seconds (e.g., 600 = 10 minutes)
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=600)
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)
        
        response = make_response(jsonify({"message" : "Login successfull"}))  
        response.headers['Authorization'] = f'Bearer {access_token}' 
        response.set_cookie('refresh_token_cookie', refresh_token, httponly=True , samesite='Strict') 

        return response
    
    except SignatureExpired:
        return 'The link has expired.', 401
    
    except BadSignature:
        return 'Invalid token.',401


@app.route('/logout',methods=['DELETE'])
@jwt_required()
def logout():
    access_token = request.headers['Authorization'].split()[1]
    refresh_token = request.cookies.get('refresh_token_cookie')
    
    # blacklist the token
    if access_token not in blackListedAccesTokens :
        blackListedAccesTokens.add(access_token)
    else : 
        return "Already logged out"
    if refresh_token not in blackListedRefreshTokens :
        blackListedRefreshTokens.add(refresh_token)    
    else : 
        return "Already logged out"
        
    current_user = get_jwt_identity()
    response = make_response(jsonify({"msg": f"User {current_user} logged out successfully"}))
    response.set_cookie('refresh_token_cookie', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return 'Logout'


@app.route('/protected')
@jwt_required()
@check_blacklist
def protected():
    return 'protected resources'


@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.cookies.get('refresh_token_cookie')

    if refresh_token in blackListedRefreshTokens :
        return "Token has already been expired!"
    
    if not refresh_token:
        return jsonify({"msg": "Missing refresh token"}), 401
    
    access_token = request.headers['Authorization'].split()[1]
    if isValidToken(access_token) :
        return jsonify({"msg": "Access token has not expired"}), 301

    try:
        # Decode and verify the refresh token
        decoded_token = jwt.decode(refresh_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        current_user = decoded_token['sub']  # Extract the identity (email or user ID)

        # If the refresh token is valid, create a new access token
        new_access_token = create_access_token(identity=current_user)

        # Return the new access token
        response = make_response(jsonify({"access_token": new_access_token}))
        response.headers['Authorization'] = f'Bearer {new_access_token}'
        return response

    except ExpiredSignatureError:
        return jsonify({"msg": "Refresh token has expired"}), 401
    except InvalidTokenError:
        return jsonify({"msg": "Invalid refresh token"}), 401

if __name__ == '__main__':
    app.run(debug=True)