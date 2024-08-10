try:
    import os
    from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, make_response
    import re
    import requests
    from flask_sqlalchemy import SQLAlchemy
    import bcrypt
    import heapq
    import qrcode
    import uuid
    import datetime
    from datetime import datetime as dt, timedelta
    import io
    from sqlalchemy import func, desc
    import pdfkit
    import secrets
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email import encoders
    from email.mime.base import MIMEBase
    import matplotlib.pyplot as plt
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy import or_
except:
    import os
    os.system('pip install flask requests flask_sqlalchemy bcrypt qrcode pdfkit matplotlib')
    from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
    import re
    import requests
    from flask_sqlalchemy import SQLAlchemy
    import bcrypt
    import heapq
    import qrcode
    import datetime
    import uuid
    from datetime import datetime as dt, timedelta
    import io
    from sqlalchemy import func, desc
    import pdfkit
    import secrets
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email import encoders
    from email.mime.base import MIMEBase
    import matplotlib.pyplot as plt
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy import or_

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'secure_secret_key_cannot_be_hacked'
db = SQLAlchemy(app)

# For mailing feature
PASSWORD = "shly ppda ekxy szyo"
USERNAME = "anonymous50137@gmail.com"

# For Captcha
SECRET_KEY = '6LcOVHUpAAAAANGFCsPc1wXBFa3fQtcZF-xGjGE0'  

# Set the path to wkhtmltopdf executable
config = pdfkit.configuration(wkhtmltopdf=r"wkhtmltopdf.exe")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    reset_password_token = db.Column(db.String(100), nullable=True)

    def __init__(self,username,first_name, last_name, email,password, reset_password_token=None):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.reset_password_token = reset_password_token
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))
    
    @classmethod
    def username_exists(cls, username):
        # Query the database to check if the username exists
        return db.session.query(db.exists().where(User.username == username)).scalar()
    @classmethod
    def email_exists(cls, email):
        # Query the database to check if the username exists
        return db.session.query(db.exists().where(User.email == email)).scalar()
    
    def set_password(self, new_password):
        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update the user's password
        self.password = hashed_password

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __init__(self, name, address, phone, email):
        self.name = name
        self.address = address
        self.phone = phone
        self.email = email

    @classmethod
    def email_exists(cls, email):
        # Query the database to check if the username exists
        return db.session.query(db.exists().where(Client.email == email)).scalar()
 
class Product(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

    def __init__(self, id, name, price):
        self.id = id
        self.name = name
        self.price = price

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.id'), nullable=False)  
    quantity = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=dt.utcnow())

    def __init__(self, product_id, quantity, timestamp=None):
        self.product_id = product_id
        self.quantity = quantity
        if timestamp is not None:
            self.timestamp = timestamp
        else:
            self.timestamp = dt.utcnow()

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    product_id = db.Column(db.String(50), db.ForeignKey('product.id'), nullable=False)
    product_quantity = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.DateTime, nullable=False)
    delivery_time = db.Column(db.DateTime, nullable=False)
    priority_status = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    qr_code_path = db.Column(db.String(200), nullable=True)

    client = db.relationship('Client', backref='orders')
    product = db.relationship('Product', backref='orders')

    def __init__(self, client_id, product_id, product_quantity, order_date, delivery_time, priority_status, status, qr_code_path=None):
        self.client_id = client_id
        self.product_id = product_id
        self.product_quantity = product_quantity
        self.order_date = order_date
        self.delivery_time = delivery_time
        self.priority_status = priority_status
        self.status = status
        self.qr_code_path = qr_code_path

class Delivery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    geo_location = db.Column(db.String(100), nullable=False)
    
    def __init__(self, id, order_id, client_id, status, geo_location):
        self.id = id
        self.order_id = order_id
        self.client_id = client_id
        self.status = status
        self.geo_location = geo_location
        
    def __repr__(self):
        return f"Delivery(id={self.id}, order_id={self.order_id}, status={self.status}, geo_location={self.geo_location})"
    
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, order_id, amount, payment_date):
        self.order_id = order_id
        self.amount = amount
        self.payment_date = payment_date

with app.app_context():
    db.create_all()

# Password strength regex pattern
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# =============================================
# Register and Login feature
# Home route
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form['username']
        password = request.form['password']

        # Verify reCAPTCHA
        captcha_response = request.form['g-recaptcha-response']
        captcha_result = requests.post('https://www.google.com/recaptcha/api/siteverify', {
            'secret': SECRET_KEY,
            'response': captcha_response
        })
        captcha_data = captcha_result.json()
        
        if captcha_data['success']:
            user = User.query.filter_by(username=username).first()
        
            if user and user.check_password(password):
                session['username'] = user.username
                flash(f"Logged in successfully!", 'success')
                return redirect(url_for('dashboard'))
            else:
                # Invalid credentials, display error message
                return render_template('index.html', error1='Invalid username or password')
        else:
            # CAPTCHA verification failed, display error message
            return render_template('index.html', error2='reCAPTCHA verification failed')

    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle registration form submission
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Verify reCAPTCHA
        captcha_response = request.form['g-recaptcha-response']
 
        captcha_result = requests.post('https://www.google.com/recaptcha/api/siteverify', {
            'secret': SECRET_KEY,
            'response': captcha_response
        })
        captcha_data = captcha_result.json()
        
        if captcha_data['success']:
            # Check if email already exists
            if User.email_exists(email):
                return render_template('register.html', error1=f'Email already exists!')
            
            # Check if username already exists
            if User.username_exists(username):
                return render_template('register.html', error2=f'Username already exists!')

            # Check password strength
            if not is_password_strong(password):
                return render_template('register.html', error3='Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character')

            # Check if passwords match
            if password != confirm_password:
                return render_template('register.html', error4='Passwords do not match!')
            
            try:
                new_user = User(username=username, first_name=first_name, last_name=last_name,email=email,password=password)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('success'))
            except:
                # Internal server error
                return render_template('500.html')
            
        else :
            return render_template('register.html', error5='reCAPTCHA verification failed')

    return render_template('register.html')

def is_password_strong(password):
    # Check if the password meets the required criteria
    return bool(re.match(PASSWORD_PATTERN, password))

@app.route('/success')
def success():
    return render_template('success.html')
# =================================================================

# Forget Password Feature

def send_password_reset_email(email, token):
    # Email content
    subject = "Password Reset Code"
    body = f"Here is your Email Reset Code: {token}"

    # Create message
    message = MIMEMultipart()
    message["From"] = USERNAME
    message["To"] = email
    message["Subject"] = subject

    # Attach body
    message.attach(MIMEText(body, "plain"))

    # Send email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(USERNAME, PASSWORD)
            connection.sendmail(USERNAME, email, message.as_string())
        print("Email sent successfully")
    except Exception as e:
        print(f"An error occurred: {e}")
        
@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generates a secure token for password reset
            reset_token = secrets.token_hex(20)  # Generates a random hex token
            user.reset_password_token = reset_token
            db.session.commit()

            # Send password reset email
            send_password_reset_email(user.email, reset_token)
            flash(f"Password reset email sent to {email}", "success")
            
            # Redirect to password reset page
            return redirect(url_for('reset_password', email=email))
        else:
            flash("Email does not exist. Please enter a valid email address.", 'error')
            return redirect(url_for('forget_password'))
    return render_template('forget_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(email=email).first()
    if user and user.reset_password_token:
        if request.method == 'POST':
            code = request.form['code']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if code != user.reset_password_token:
                flash("Invalid reset code. Please enter the correct code.", 'error')
                return redirect(url_for('reset_password', email=email))
            elif new_password != confirm_password:
                flash("Passwords do not match. Please try again.", 'error')
                return redirect(url_for('reset_password', email=email))
            elif not is_password_strong(new_password):
                flash("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character", 'error')
                return redirect(url_for('reset_password', email=email))
            else:
                # Reset user's password
                user.set_password(new_password)
                user.reset_password_token = None
                db.session.commit()
                flash("Your password has been reset successfully. You can now log in with your new password.", 'success')
                return redirect(url_for('login'))
        return render_template('reset_password.html', email=email)
    else:
        flash("Invalid or expired reset link. Please request a new reset link.", 'error')
        return redirect(url_for('forget_password'))

# =================================================================

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect('/login')

# Logout route
@app.route('/logout')
def logout():
    # Clear session and redirect to home page
    session.clear()
    return redirect(url_for('login'))

# =============================================

# Clients routes
@app.route('/clients')
def clients():
    # Fetch and display clients data
    return render_template('client.html')

# Route for adding a new client
@app.route('/add_client', methods=['POST'])
def add_client():
    # Get client data from the form
    name = request.form['client_name']
    address = request.form['client_address']
    phone = request.form['client_phone']
    email = request.form['client_email']
    
    if Client.email_exists(email):
        return render_template('client.html', error1=f'Email already exists!')
    
    # Create a new client object
    new_client = Client(name=name, address=address, phone=phone, email=email)
    
    # Add the client to the database
    db.session.add(new_client)
    db.session.commit()
    
    flash(f"New client '{name}' is added", 'success')
    
    # Redirect to the clients page
    return redirect(url_for('clients'))

# Route for searching clients
@app.route('/search_clients')
def search_clients():
    # Get the search query from the request parameters
    query = request.args.get('query')

    # Query the database for clients matching the search query
    clients = Client.query.filter(
        (Client.name.contains(query)) |
        (Client.address.contains(query)) |
        (Client.phone.contains(query)) |
        (Client.email.contains(query))
    ).all()
    if not clients:
        flash(f"No clients found with the search query '{query}'", 'info')
        return redirect(url_for('clients'))
    # Render the clients.html template with the search results
    return render_template('client.html', clients=clients)

# Edit Client
@app.route('/edit_client/<int:client_id>', methods=['GET', 'POST'])
def edit_client(client_id):
    # Get the client from the database
    client = Client.query.get_or_404(client_id)
    
    # Handle form submission for editing client details
    if request.method == 'POST':
        client.name = request.form['client_name']
        client.address = request.form['client_address']
        client.phone = request.form['client_phone']
        given_email = request.form['client_email']
        
        # Check if the given email is already in use
        if given_email != client.email:
            existing_client = Client.query.filter_by(email=given_email).first()
            if existing_client:
                flash(f"Email address '{given_email}' is already in use!", "error")
                return redirect(url_for('edit_client', client_id=client_id))
        
        # Update the client's data and commit changes
        client.email = given_email
        db.session.commit()
        flash(f"Client's data updated!", 'success')
        return redirect(url_for('clients'))
    
    # Render the edit client form
    return render_template('edit_client.html', client=client)

# Route for deleting a client
@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    # Get the client from the database
    client = Client.query.get_or_404(client_id)
    
    # Delete the client from the database
    db.session.delete(client)
    db.session.commit()
    flash(f"Client with ID '{client_id}' is deleted", 'success')
    
    return redirect(url_for('clients'))

# ===============================================
from datetime import datetime

# Orders route
@app.route('/orders')
def orders():
    # Fetch and display orders data
    orders = Order.query.all()
    return render_template('order.html', orders=orders)

# Function to generate QR code for order confirmation
def generate_qr_code(order_id):
    # Directory to save the QR codes
    qr_code_dir = 'static/qr_codes/'
    
    # Create the directory if it doesn't exist
    os.makedirs(qr_code_dir, exist_ok=True)
    
    # Generate QR code with order ID as data
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(order_id)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Save the QR code image
    qr_code_path = os.path.join(qr_code_dir, f'order_{order_id}.png')
    qr_img.save(qr_code_path)
    
    return qr_code_path

# Create order
# Function to create a new order
def create_new_order(client_id, product_id, quantity, order_date, priority_status):
    quantity = int(quantity)
    # Retrieve stock information for the product
    stock_info = Stock.query.filter_by(product_id=product_id).first()
    if not stock_info:
        flash("Stock information not found for the product.", "error")
        return None

    # Check if the ordered quantity is more than available in stock
    if quantity > stock_info.quantity:
        flash(f"Quantity available for this Product: {stock_info.quantity}", "error")
        return None
    
    # Convert the order_date string to datetime
    order_date = datetime.strptime(order_date, '%Y-%m-%dT%H:%M')

    delivery_time = order_date 

    # Placeholder status
    status = "Pending"

    # Generate UUID for order ID
    order_id = str(uuid.uuid4())

    # Generate QR code for order confirmation
    qr_code_path = generate_qr_code(order_id)

    # Create a new order instance
    new_order = Order(client_id=client_id, product_id=product_id, product_quantity=quantity,
                      order_date=order_date,
                      delivery_time=delivery_time,
                      priority_status=priority_status,
                      status=status,
                      qr_code_path=qr_code_path)

    db.session.add(new_order)
    db.session.commit()
    return new_order

def shift_to_stack(product_id, quantity):
    # Retrieve stock information for the product
    stock_info = Stock.query.filter_by(product_id=product_id).first()
    if not stock_info:
        flash("Stock information not found for the product.", "error")
        return False

    # Check if the ordered quantity is more than available in stock
    if int(quantity) > int(stock_info.quantity):
        flash(f"Quantity available for this Product: {stock_info.quantity}", "error")
        return False
    
    return True

# Route to create a new order
@app.route('/create_order', methods=['POST'])
def create_order():
    # Get form data
    client_id = request.form['client_id']
    product_id_or_name = request.form['product_id_or_name']
    quantity = request.form['quantity']
    order_date = request.form['order_date']
    priority_status = request.form['priority']

    # Retrieve client details from the database
    client = Client.query.filter_by(id=client_id).first()
    if not client:
        flash("Client not found.", "error")
        return redirect(url_for("orders"))

    # Retrieve product details using product ID or name from the product table in the database
    product = Product.query.filter_by(id=product_id_or_name).first()
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("orders"))

    # Create new order
    order_data = create_new_order(client_id, product_id_or_name, quantity, order_date, priority_status)
    if order_data:
        product_shifted_to_stack = shift_to_stack(product.id, quantity)
        # Render a template with the order details
        return render_template('order_confirmation.html', order=order_data, client=client)

    return redirect(url_for("orders"))

from datetime import datetime

# Route to confirm an order
@app.route('/confirm_order/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    # Retrieve the order from the database
    order = Order.query.get(order_id)
    if order:
        # Update the order status to confirmed
        order.status = "Confirmed"
        
        # Commit the order status update to the database
        db.session.commit()
        
        # Deduct the quantity from the stock
        stock_info = Stock.query.filter_by(product_id=order.product_id).first()
        if stock_info:
            # Check if there is enough quantity in stock
            if stock_info.quantity >= order.product_quantity:
                # Reduce the quantity in stock
                stock_info.quantity -= order.product_quantity
                db.session.commit()
                
                # Add a record to the Payment table
                amount_to_pay = order.product_quantity * order.product.price
                payment = Payment(order_id=order.id, amount=amount_to_pay, payment_date=datetime.now())
                db.session.add(payment)
                db.session.commit()
                
                flash("Order confirmed successfully and payment recorded.", "success")
            else:
                flash("Insufficient quantity in stock to fulfill the order.", "error")
        else:
            flash("Stock information not found for the product.", "error")
    else:
        flash("Order not found.", "error")
    return redirect(url_for("orders"))


# Route to cancel an order
@app.route("/cancel_order/<int:order_id>", methods=["POST"])
def cancel_order(order_id):
    # Retrieve the order from the database
    order = Order.query.get(order_id)
    if order:
        # Update the order status to Cancelled
        order.status = "Cancelled"
        db.session.commit()
    else:
        flash("Order not found.", "error")
    return redirect(url_for("orders"))

# def binary_search_order(orders, target_order_id):
#     left, right = 0, len(orders) - 1

#     while left <= right:
#         mid = left + (right - left) // 2
#         mid_order = orders[mid]

#         if int(mid_order.id) == int(target_order_id):
#             return mid_order
#         elif int(mid_order.id) < int(target_order_id):
#             left = mid + 1
#         else:
#             right = mid - 1

#     return None

# Route for searching an order by ID
@app.route('/search_order', methods=['GET', 'POST'])
def search_page():
    return render_template("search_order.html")

# Route to search for an order by ID using binary search
# @app.route('/order_details', methods=['GET', 'POST'])
# def search_order():
#     if request.method == 'POST':
#         order_id = request.form['search']

#         # Retrieve all orders and sort them by ID
#         orders = sorted(Order.query.all(), key=lambda x: x.id)

#         # Perform binary search
#         order = binary_search_order(orders, order_id)

#         if order:
#             # Fetch the client's address
#             client = Client.query.get(order.client_id)
#             if client:
#                 order.client_address = client.address
#             else:
#                 order.client_address = "Address not found"

#             product = Product.query.get(order.product_id)
#             return render_template('order_details.html', order=order, product=product)
#         else:
#             flash("Order not found.", "error")
#             return redirect(url_for("search_order"))
#     else:
#         return render_template("search_order.html")


# # Route for searching an order by ID
@app.route('/order_details', methods=['GET', 'POST'])
def search_order():
    if request.method == 'POST':
        order_id = request.form['search']
        order = Order.query.get(order_id)
        if order:
            # Fetch the client's address
            client = Client.query.get(order.client_id)
            if client:
                order.client_address = client.address
            else:
                order.client_address = "Address not found"
            product = Product.query.get(order.product_id)
            return render_template('order_details.html', order=order, product=product)
        else:
            flash("Order not found.", "error")
            return redirect(url_for("search_order"))
    else:
        return render_template("search_order.html")

# Route to render edit form for an order
@app.route('/edit_order/<int:order_id>', methods=['GET'])
def edit_order(order_id):
    order = Order.query.get(order_id)
    if order:
        return render_template('edit_order.html', order=order)
    else:
        flash("Order not found.", "error")
        return redirect(url_for("orders")) 

# Route to handle edit form submission
@app.route('/update_order/<int:order_id>', methods=['POST'])
def update_order(order_id):
    order = Order.query.get(order_id)
    if order:
        # Get the new quantity from the form
        new_quantity = int(request.form['product_quantity'])
        quantity_difference = new_quantity - order.product_quantity
            
        # Update order details
        order.client_id = request.form['client_id']
        order.product_id = request.form['product_id']
        order.product_quantity = new_quantity
        order.order_date = dt.strptime(request.form['order_date'], '%Y-%m-%dT%H:%M')
        order.delivery_time = dt.strptime(request.form['delivery_time'], '%Y-%m-%dT%H:%M')
        order.priority_status = request.form['priority']
        order.status = request.form['status']
        
        if new_quantity <= 0:
            flash("Quantity can't be zero.", "error")
            return redirect(url_for("orders"))

        # If the new quantity is greater than the previous quantity, deduct the difference from the product quantity
        if quantity_difference > 0:
            stock_info = Stock.query.filter_by(product_id=order.product_id).first()
            if stock_info:
                if stock_info.quantity < quantity_difference:
                    flash("Stock Insuficient")
                    return redirect(url_for("orders"))
                
                stock_info.quantity -= quantity_difference
                db.session.commit()
            else:
                flash("Stock information not found for the product.", "error")
        elif quantity_difference < 0:
            stock_info = Stock.query.filter_by(product_id=order.product_id).first()
            if stock_info:
                stock_info.quantity += abs(quantity_difference)
                db.session.commit()
                
        db.session.commit()
        flash("Order updated successfully.", "success")
    else:
        flash("Order not found.", "error")
    return redirect(url_for("orders"))

# Route to handle deletion of an order
@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    order = Order.query.get(order_id)
    if order:
        db.session.delete(order)
        db.session.commit()
        flash("Order deleted successfully.", "success")
    else:
        flash("Order not found.", "error")
    return redirect(url_for("orders"))


# =============================================
# Stock route
@app.route('/stock')
def stock():
    # Get all products
    all_products = Product.query.all()
    
    # Get low stock products
    low_stock_products = get_low_stock_products()

    # Get all stock data
    all_stock_data = get_all_stock_data()

    # Render the stock.html template with all products, low stock products, and all stock data
    return render_template('stock.html', products=all_products, low_stock_products=low_stock_products, all_stock_data=all_stock_data, searched_product=None)


# Function to get all stock data
def get_all_stock_data():
    all_stock_data = []
    all_stock_items = Stock.query.all()
    for stock_item in all_stock_items:
        product = Product.query.get(stock_item.product_id)
        all_stock_data.append((product, stock_item))
    return all_stock_data


# Function to get low stock products
def get_low_stock_products(threshold=20):
    # Query the database to find products with quantity below the threshold
    low_stock_products = []
    low_stock_stocks = Stock.query.filter(Stock.quantity < threshold).all()
    for stock in low_stock_stocks:
        product = Product.query.get(stock.product_id)
        low_stock_products.append((product, stock.quantity))
    return low_stock_products


# Route for adding new stock
@app.route('/add_stock', methods=['POST'])
def add_stock():
    # Get stock data from the form
    product_name = request.form['product_name']
    product_id = request.form['product_id']
    quantity = request.form['quantity']
    price = request.form['price']
    
    # Check if product ID already exists
    existing_stock = Stock.query.filter_by(product_id=product_id).first()
    if existing_stock:
        # If product exists, check if the product name matches
        existing_product = Product.query.get(product_id)
        if existing_product and existing_product.name != product_name:
            flash(f"Product name is different for product ID '{product_id}'.", 'error')
            return redirect(url_for('stock'))  # Redirect to the stock route
        # Update quantity if product already exists
        existing_stock.quantity += int(quantity)
    else:
        # Create a new product object
        new_product = Product(id=product_id, name=product_name, price=price)
        db.session.add(new_product)
        
        # Create a new stock object
        new_stock = Stock(product_id=product_id, quantity=quantity)
        db.session.add(new_stock)
    
    db.session.commit()
    
    flash(f"New stock added for product '{product_name}'", 'success')
    return redirect(url_for('stock'))  # Redirect to the stock route
    

# Search for products
    
@app.route('/search_stock', methods=['GET'])
def search_stock():
    query = request.args.get('query')

    # Search for the product by ID or name
    product = Product.query.filter(or_(Product.id == query, Product.name == query)).first()
    low_stock_products = get_low_stock_products()

    if product:
        # Get the stock data for the searched product
        stock = Stock.query.filter_by(product_id=product.id).first()

        # Render the stock-searched-section with the searched product and its stock data
        return render_template('stock.html', searched_product=product, low_stock_products=low_stock_products, searched_stock=stock, all_stock_data=None)  
    else:
        # If no product is found, return a message or handle it as needed
        flash(f"Product not found for ID {query}")
        return redirect(url_for('stock'))


            
# Route for editing a stock item
@app.route('/edit_stock/<int:product_id>', methods=['GET', 'POST'])
def edit_stock(product_id):
    # Get the stock from the database
    stock = Stock.query.get_or_404(product_id)
    product = Product.query.get_or_404(product_id)
    
    # Handle form submission for editing stock details
    if request.method == 'POST':
        stock.quantity = request.form['quantity']
        
        product.name = request.form['product_name']
        product.price = request.form['price']
        db.session.commit()
        flash(f"Stock details updated for product ID '{stock.product_id}'", 'success')
        return redirect(url_for('stock'))
    
    # Render the edit stock form
    return render_template('edit_stock.html', stock=stock, product=product)


@app.route('/delete_stock/<int:product_id>', methods=['POST'])
def delete_stock(product_id):
    try:
        # Get the stock from the database
        stock = Stock.query.get_or_404(product_id)
        product = Product.query.get_or_404(product_id)

        # Check if there are any orders associated with this product
        associated_orders = Order.query.filter_by(product_id=product_id).all()

        # Handle associated orders
        for order in associated_orders:
            db.session.delete(order)  # You may want to update the product_id instead of deleting orders

        # Now it's safe to delete the product and stock
        db.session.delete(product)
        db.session.delete(stock)
        db.session.commit()
        
        flash(f"Stock for product ID '{stock.product_id}' is deleted", 'success')

    except IntegrityError:
        db.session.rollback()  # Rollback the transaction in case of integrity error
        flash("Failed to delete stock. Some orders are associated with this product.", 'error')

    return redirect(url_for('stock'))


# ========================================================

# Invoices route
invoice_html=False
@app.route('/invoices', methods=['GET'])
def view_invoice():
    clients = Client.query.all()
    return render_template('invoice.html', clients=clients)


# View Invoice
@app.route('/display_invoice', methods=['GET'])
def display_invoice():
    return invoice_html

def generate_invoice_pdf():
    global invoice_html
    pdf=pdfkit.from_string(invoice_html, False, configuration=config)
    return pdf


@app.route('/save_invoice', methods=['POST'])
def save_invoice():
    client_id = request.form['client_id']
    order_id = request.form['order_id']
    edited_invoice = request.form['edited_invoice']

    # Call the generate_invoice function passing the client_id, order_id, and edited_invoice
    generate_invoice(client_id, order_id, edited_invoice)



# Route for sending invoices
@app.route('/send_invoice', methods=['GET'])
def send_invoice():
    # Retrieve email from the request
    global invoice_html
    email =request.args.get("email","")
    # Convert HTML to PDF
    pdf = generate_invoice_pdf()
    if pdf:
        # Prepare email message
        msg = MIMEMultipart()
        msg['From'] =USERNAME  # Update with your email address
        msg['To'] = email
        msg['Subject'] = 'Invoice'

        # Attach PDF file
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(pdf)
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment', filename='invoice.pdf')
        msg.attach(attachment)

        # Connect to SMTP server and send email
        with smtplib.SMTP('smtp.gmail.com') as server:  # Update with your SMTP server details
            server.starttls()
            server.login(USERNAME,PASSWORD)  # Update with your email and password
            server.send_message(msg=msg,from_addr=USERNAME,to_addrs=email)

        return "Invoice sent successfully."
    else:
        return "Error: Failed to convert HTML to PDF"

@app.route('/delete_invoice', methods=['GET'])
def delete_invoice():
    client_id = request.args.get('client_id')
    order_id = request.args.get('order_id')
    filename = f"{client_id}_{order_id}.pdf"
    file_path = os.path.join(app.static_folder, 'Invoices', filename)
    try:
        os.remove(file_path)
        return 'Invoice deleted successfully.', 200
    except FileNotFoundError:
        return 'Invoice not found.', 404
    except Exception as e:
        return f'An error occurred: {str(e)}', 500

@app.route('/generate_invoice', methods=['POST'])
def generate_invoice():
    client_id = request.form['client_id']
    order_id = request.form['order_id']
    
    # Fetch client and order details from the database
    client = Client.query.get(client_id)
    order = Order.query.get(order_id)
    
    # Render invoice dynamically
    global invoice_html
    invoice_html = render_template('invoice_template.html', client=client, order=order)
    
    # Generate PDF file
    pdf_data = generate_invoice_pdf()
    
    # Save PDF file to local storage
    folder_path = os.path.join(app.static_folder, 'Invoices')
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    pdf_path = os.path.join(folder_path, f"{client_id}_{order_id}.pdf")
    save_pdf_file(pdf_data, pdf_path)
    
    return "Invoice generated and saved successfully."

def save_pdf_file(pdf_data, pdf_path):
    # Save PDF data to file
    with open(pdf_path, 'wb') as file:
        file.write(pdf_data)

    
# Route for Downloading Invoice
@app.route('/download_invoice', methods=['GET'])
def download_invoice():
    # Convert HTML to PDF
    pdf =generate_invoice_pdf()
    if pdf:
        # Send PDF file as a response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=invoice.pdf'
        return response
    else:
        # Handle the case where PDF conversion fails
        return "Error: Failed to convert HTML to PDF"


@app.route('/get_orders', methods=['GET'])
def get_orders():
    client_id = request.args.get('client_id')
    orders = Order.query.filter_by(client_id=client_id).all()
    orders_data = [{'id': order.id} for order in orders]
    return jsonify({'orders': orders_data})
     
# ========================================================

# Reports route
@app.route('/reports')
def reports():
    # Fetch and display reports data
    return render_template('report.html')

# function to combine multiple PDFs
def combine_reports(*report_contents):
    combined_pdf = io.BytesIO()
    for content in report_contents:
        combined_pdf.write(content)
    combined_pdf.seek(0)
    return combined_pdf.getvalue()

# Function to render HTML template and download PDF
def render_and_download_pdf(html_content, filename):
    pdf_bytes = pdfkit.from_string(html_content, False, configuration=config)
    return pdf_bytes


# Client details report
@app.route('/reports/client_details')
def generate_client_report():
    # Query to get top 10 clients based on total orders
    clients_data = db.session.query(
        Client.id.label('client_id'),  # Include client ID in the query
        Client.name.label('client_name'),
        Client.address.label('client_address'),
        Client.phone.label('client_phone'),
        Client.email.label('client_email'),
        func.count(Order.id).label('total_orders')
    ).outerjoin(Order).group_by(Client.id).order_by(desc('total_orders')).limit(10).all()

    html_content = render_template('client_report.html', clients=clients_data)
    return render_and_download_pdf(html_content, 'client_report.pdf')


# Product details report
@app.route('/reports/product_details')
def generate_product_report():
    products = Product.query.all() 
    stokes = Stock.query.all()
    html_content = render_template('product_report.html', products=products, stocks=stokes)
    return render_and_download_pdf(html_content, 'product_report.pdf')

# Stock details report (Time driven)
@app.route('/reports/stock_details')
def generate_stock_report():
    current_time = dt.utcnow()
    start_time = current_time - timedelta(hours=24)
    stock_details = Stock.query.filter(Stock.timestamp >= start_time).all()
    html_content = render_template('stock_report.html', stock_details=stock_details)
    return render_and_download_pdf(html_content, 'stock_report.pdf')

from datetime import date

# Order details report (Time driven)
@app.route('/reports/order_details')
def generate_order_report():
    current_date = date.today()
    # Calculate the start date by subtracting 7 days from the current date
    start_date = current_date - timedelta(days=7)
    # Query orders within the last 7 days
    orders = Order.query.filter(Order.order_date >= start_date).all()

    # Calculate total amount for each order
    for order in orders:
        payment = Payment.query.filter_by(order_id=order.id).first()       
        if payment:
            order.total_amount = payment.amount
        else:
            order.total_amount = 0  

    html_content = render_template('order_report.html', orders=orders)
    return render_and_download_pdf(html_content, 'order_report.pdf')


# Route for generating payment report
@app.route('/reports/payment_details')
def generate_payment_report():
    current_month = date.today().month
    payments = Payment.query.filter(func.extract('month', Payment.payment_date) == current_month).all()
    
    # Fetch the client names associated with each payment
    for payment in payments:
        order = Order.query.filter_by(id=payment.order_id).first()
        if order:
            client = Client.query.filter_by(id=order.client_id).first()
            if client:
                payment.client_name = client.name  # Add client name to the payment object
    
    html_content = render_template('payment_report.html', payments=payments)
    return render_and_download_pdf(html_content, 'payment_report.pdf')


# Route for generating individual reports
@app.route('/generate_report', methods=['POST'])
def generate_report():
    report_type = request.form.get('report_type')

    if report_type == 'client-details':
        report_content = generate_client_report()
        filename = 'client_report.pdf'
    elif report_type == 'product-details':
        report_content = generate_product_report()
        filename = 'product_report.pdf'
    elif report_type == 'stock-details':
        report_content = generate_stock_report()
        filename = 'stock_report.pdf'
    elif report_type == 'order-details':
        report_content = generate_order_report()
        filename = 'order_report.pdf'
    elif report_type == 'payment-details':
        report_content = generate_payment_report()
        filename = 'payment_report.pdf'
    else:
        return "Invalid report type selected"

    return send_file(
        io.BytesIO(report_content),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

# Route for requesting graphs
@app.route('/view_statistics', methods=['POST'])
def view_statistics():
    image_url = None
    graph_type = request.form.get('stats_type')

    if graph_type == 'order_graph':
        current_date = date.today()
        start_date = current_date - timedelta(days=7)
        orders = Order.query.filter(Order.order_date >= start_date).all()

        for order in orders:
            payment = Payment.query.filter_by(order_id=order.id).first()
            order.total_amount = payment.amount if payment else 0

        image_url = generate_order_graph(orders)
        # return render_template('report.html', image_url=image_url)

    elif graph_type == 'product_graph':

        products = Product.query.all() 
        stocks = Stock.query.all()

        product_names = [product.name for product in products]
        stock_quantities = [stock.quantity for stock in stocks]

        # Generate and save the bar graph
        image_url = generate_product_graph(product_names, stock_quantities, 'Product Stock Details', 'product_stock_graph')
        # return render_template('report.html', image_url=image_url)

    elif graph_type == 'stock_graph':
        current_time = dt.utcnow()
        start_time = current_time - timedelta(hours=24)
        stock_details = Stock.query.filter(Stock.timestamp >= start_time).all()
        
        # Generate the stock graph
        image_url = generate_stock_graph(stock_details)
        # return render_template('report.html', image_url=image_url)
    else:
        flash("Invalid Graph type selected", 'error')
        return redirect(url_for('reports'))

    return render_template('report.html', image_url=image_url)


# =================== Generate Graphs ==================================

def generate_product_graph(x_labels, y_values, title, filename):
    plt.figure(figsize=(10, 6))
    plt.bar(x_labels, y_values)
    plt.xlabel('Products')
    plt.ylabel('Quantity')
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Saving the graph image
    graph_filename = 'product_graph.png'
    graph_path = os.path.join('static', 'graphs', graph_filename)
    os.makedirs(os.path.dirname(graph_path), exist_ok=True)  
    plt.savefig(graph_path)
    return graph_path

from collections import Counter

def generate_order_graph(orders):
    # Extracting order dates for plotting
    order_dates = [order.order_date.strftime('%Y-%m-%d') for order in orders]

    # Counting the number of orders per date
    order_counts = Counter(order_dates)

    # Extracting unique dates and their corresponding order counts
    unique_dates = list(order_counts.keys())
    order_counts_list = list(order_counts.values())

    # Plotting the graph
    plt.figure(figsize=(10, 6))
    plt.bar(unique_dates, order_counts_list, color='skyblue')
    plt.xlabel('Order Date')
    plt.ylabel('Number of Orders')
    plt.title('Number of Orders per Date')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Saving the graph image
    graph_filename = 'order_graph.png'
    graph_path = os.path.join('static', 'graphs', graph_filename)
    os.makedirs(os.path.dirname(graph_path), exist_ok=True)
    plt.savefig(graph_path)

    return graph_path


# Function to generate and save the stock graph
def generate_stock_graph(stock_details):
    # Extracting timestamps and quantities for plotting
    timestamps = [stock.timestamp.strftime('%Y-%m-%d %H:%M:%S') for stock in stock_details]
    quantities = [stock.quantity for stock in stock_details]

    # Plotting the graph
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, quantities, marker='o', linestyle='-', color='skyblue')  # Line plot with markers
    plt.xlabel('Timestamp')
    plt.ylabel('Quantity')
    plt.title('Stock Quantity Over Time')
    plt.xticks(rotation=45, ha='right')
    plt.grid(True)  # Add grid for better visualization
    plt.tight_layout()

    # Saving the graph image
    graph_filename = 'stock_graph.png'
    graph_path = os.path.join('static', 'graphs', graph_filename)

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(graph_path), exist_ok=True)
    plt.savefig(graph_path)
    return graph_path


# =================================================

# Delivery routes
@app.route('/delivery')
def delivery():
    db.session.query(Delivery).delete()
    # Fetch orders from the database
    orders = Order.query.all()
    # List to hold delivery instances
    confirmed_deliveries = []
    id=1
    # Iterate through orders to create delivery instances
    for order in orders:
        delivery_id = id
        delivery_address = order.client.address
        delivery_date = order.delivery_time
        current_date = datetime.now()
        print(current_date)
        print(delivery_date)
        id+=1
        if current_date >= delivery_date:
            status = "Completed"
        else:
            status = "Processing"
        
        # Create a delivery instance
        for_db_delivery = Delivery(
            id=delivery_id,
            order_id=order.id,
            client_id=order.client_id,
            geo_location=delivery_address,
            status=status
        )
        to_print_dict={
            'id': delivery_id,
            'order_id': order.id,
            'client_id': order.client_id,
            'delivery_address': delivery_address,
            'delivery_date': delivery_date,
            'status': status
        }
        if to_print_dict["status"]=="Completed":
        # Add the delivery instance to the list
            confirmed_deliveries.append(to_print_dict)

        # Add the delivery instance to the database session
        db.session.add(for_db_delivery)

    # Commit the session to save the changes to the database
    db.session.commit()

    # Render the template with the list of delivery instances
    return render_template('delivery.html', deliveries=confirmed_deliveries, delivery1=None)

# Modify the search_delivery route to return JSON data
@app.route('/search_delivery')
def search_delivery():
    delivery_id = request.args.get('delivery_id')
    delivery = Delivery.query.filter_by(id=delivery_id).first()
    order = Order.query.filter_by(id=delivery.order_id).first()
    delivery_date=order.delivery_time
    if order:
        if delivery:
            return jsonify({
                'id': delivery.id,
                'order_id': delivery.order_id,
                'client_id': delivery.client_id,
                'delivery_address': delivery.geo_location,
                'delivery_date': delivery_date,
                'status': delivery.status
            })
    else:
        return jsonify({'error': 'Delivery not found'}), 404

# Route for prioritizing deliveries based on days left and needed for deliver
@app.route('/prioritize_deliveries')
def prioritize_deliveries():
    # Fetch all deliveries from the database
    deliveries = Delivery.query.all()
    
    # Create a priority queue to hold deliveries
    priority_queue = []
    
    for delivery in deliveries:
        order = Order.query.filter_by(id=delivery.order_id).first()
        delivery_date = order.delivery_time
        
        # Calculate the number of days left for delivery
        time_left = (delivery_date - datetime.now())
        
        # Check if the delivery time has not already passed
        if time_left.total_seconds() > 0:
            # Calculate priority based on days left and time within the day
            # Adjust the priority based on the remaining time within the current day
            priority = time_left.days * 24 + time_left.seconds / 3600
            
            # Push delivery ID and priority into the priority queue
            heapq.heappush(priority_queue, (priority, delivery.id))
    
    # Extract the delivery IDs from the priority queue
    prioritized_deliveries = []
    for _, delivery_id in priority_queue:
        delivery = Delivery.query.filter_by(id=delivery_id).first()
        order = Order.query.filter_by(id=delivery.order_id).first()
        delivery_date = order.delivery_time
        
        # Construct delivery dictionary
        delivery_dict = {
            'id': delivery.id,
            'order_id': delivery.order_id,
            'client_id': delivery.client_id,
            'delivery_address': delivery.geo_location,
            'delivery_date': delivery_date.strftime('%Y-%m-%d'),  # Format date as string
            'status': delivery.status
        }
        prioritized_deliveries.append(delivery_dict)
    
    # Return the prioritized list of delivery dictionaries
    return jsonify({'prioritized_deliveries': prioritized_deliveries})

# ============================================================
# Error handling routes
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
