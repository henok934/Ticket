#!/usr/bin/python3
from flask import Blueprint, flash, redirect, url_for, request
from models import storage
from models.bus import Bus
from models.admin import Admin
from flask import Flask, render_template, request, redirect, url_for, session
"""import requests"""
from flask import Flask, request
from models.route import Route
from models.city import City
from models.ticket import Ticket
from models.comment import Fedback
from models.user import User
from flask import Flask, render_template
from flask_login import login_required, current_user, login_user
from uuid import uuid4
from hashlib import md5
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
views = Blueprint('views', __name__)

from flask import Flask, render_template
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def add_no_cache_header(response):
    response.headers['Cache-Control'] = 'no-store'  # Set the Cache-Control header to 'no-store'
    return response

@views.route('/root')
def root():
    return render_template('checkroot.html', route=route)
@app.route('/users/<string:email>')
def get_user(email):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE first_name=?", (email,))
    result = c.fetchone()
    conn.close()

    if result:
        user = {'id': result[0], 'fnam': result[1], 'lname': result[2], 'email': result[3]}
        return jsonify(user)
    else:
        return jsonify({'error': 'User not found'}), 404

@views.route('/ticket_number')
def ticket_number():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tickets')
    tickets = cursor.fetchall()
    for ticket in tickets:
        conn.close()
    return render_template('ticket.html', tickets=tickets)
# Define a route to display all users
@views.route('/users')
def users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    for user in users:
        conn.close()
    return render_template('users.html', users=users)

@views.route('/comments')
def comments():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments')
    comments  = cursor.fetchall()
    for coment in comments:
        conn.close()
    return render_template('comments.html', comments=comments)
"""
@app.route('/logedin', methods=['GET', 'POST'])
def logedin():
    if request == "post":
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
    
        # Perform authentication logic here
        if role == 'admin':
            # Connect to the admin table in the database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            # Query the admin table for the provided username and password
            cursor.execute("SELECT * FROM admins WHERE username=? AND password=?", (username, password))
            admin = cursor.fetchone()

            if admin:
            # Successful authentication, redirect to admin page
                return redirect('/ad')
            else:
                # Invalid credentials, redirect back to login page
                return redirect('/login')
        else:
            # Connect to the user table in the database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            # Query the user table for the provided username and password
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            user = cursor.fetchone()

            if user:
                # Successful authentication, redirect to user page
                return redirect(url_for('profile'))
            else:
                # Invalid credentials, redirect back to login page
                return redirect('/login')
    return render_template('login.html')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users  WHERE username = ? AND password = ? AND role = ?", (username, password, role))
        c.execute("SELECT * FROM admins  WHERE username = ? AND password = ? AND role = ?", (username, password, role))
        profile = c.fetchone()
        conn.close()

        if profile:
            session['username'] = username
            session['role'] = role
            if role == 'user':
                return redirect(url_for('profile'))
            elif role == 'admin':
                return redirect(url_for('ad'))
        else:
            return render_template('login.html', error='Invalid username, password, or role')

    return render_template('login.html')


    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
    if user:
        return redirect(url_for('profile'))
    else:
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')
"""
@views.route('/routes')
def routes():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM routes')
    routes  = cursor.fetchall()
    for rout in routes:
        conn.close()
    return render_template('routes.html', routes=routes)

@views.route('/selectbus')
def selectbus():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM buses')
    data  = cursor.fetchall()
    for bus in data:
        conn.close()
    return render_template('route.html', data=data)
@views.route('/buses')
def buses():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM buses')
    buses  = cursor.fetchall()
    for bus in buses:
        conn.close()
    return render_template('buses.html', buses=buses)

@views.route('/home')
@views.route('/')
def home():
    return render_template('index.html', user=current_user)

@views.route('/about')
def about():
    """About us page"""
    return render_template('about.html', user=current_user)

@views.route('/offers')
def offers():
    """"About us page"""
    return render_template('cheeckrout.html', user=current_user)

@views.route('/ticket', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/ticket')
def ticket():
    if request.method == 'POST':
        users = storage.all(Ticket).values()
        user_ids = [user.user_id for user in users]
        data = request.form
        print(data)
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        depcity = data.get('depcity')
        descity = data.get('descity')
        price = data.get('price')
        no_seat = data.get('no_seat')
        side_no = data.get('side_no')
        date = data.get('date')
        plate_no = data.get('plate_no')
        phone = data.get('phone')
        user_id = data.get('user_id')
    if len(phone) != 10:
        flash("Please insert a valid phone number")
        return render_template('ticket.html', user=current_user)
    else:
        info = {
            "firstname": firstname,
            "lastname": lastname,
            "depcity": depcity,
            "descity": descity,
            "phone": phone,
            "date": date,
            "price": price,
            "no_seat": no_seat,
            "side_no": side_no,
            "plate_no": plate_no,
            "user_id": user_id
        }
        new_account = Ticket(**info)
        new_account.save()
        return render_template('ticket.html',user=current_user)
    return render_template('ticket.html', user=current_user)

@views.route('/businsert', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/businsert')
def businsert():
    if request.method == 'POST':
        buses = storage.all(Bus).values()
        plate_nos = [user.plate_no for user in buses]
        sidenos = [user.sideno for user in buses]
        no_seatss = [user.no_seats for user in buses]
        data = request.form
        print(data)
        plate_no = data.get('plate_no')
        sideno = data.get('sideno')
        no_seats = data.get('no_seats')
        if plate_no in plate_nos:
            flash("this plate no is registored", category="error")
        elif sideno in sidenos:
            flash("this sideno is registerd", category="error")
        else:
            info = {"plate_no": plate_no, "sideno": sideno, "no_seats": no_seats}
            new_account = Bus(**info)
            new_account.save()
            flash("ticket booked successfully", category='success')
            return redirect(url_for('views.businsert'))
    return render_template('Businsert.html', user=current_user)
@views.route('/comment', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/comment')
def comment():
    if request.method == 'POST':
        coments = storage.all(Fedback).values()
        names = [user.name for user in coments]
        messages = [user.message for user in coments]
        emails = [user.email for user in coments]
        phones = [user.phone for user in coments]
        data = request.form
        print(data)
        message = data.get('message')
        email = data.get('email')
        phone = data.get('phone')
        name = data.get('name')
        if email in emails:
            flash("email is already existed", category="error")
        else:
            info = {"message": message, "email": email, "phone": phone, "name": name}
            new_account = Fedback(**info)
            new_account.save()
            flash("coment successfully submitted!!", category='success')
            return redirect(url_for('views.comment'))
    return render_template('comment.html', user=current_user)
@views.route('/route', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/route')
def route():
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM buses')
    data  = cursor.fetchall()
    conn.close()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT depcity FROM cities')
    city  = cursor.fetchall()
    conn.close()
    conn = sqlite3.connect('database.db')
    cursor.execute('SELECT descity FROM cities')
    des  = cursor.fetchall()
    conn.close()
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM buses')
    data = cursor.fetchall()

    print(data)

    cursor.execute('SELECT depcity FROM cities')
    city = cursor.fetchall()

    cursor.execute('SELECT descity FROM cities')
    des = cursor.fetchall()

    cursor.close()
    conn.close()
    """
    raw_cities = storage.all(City)
    des = [city.to_dict() for city in raw_cities.values()]
    data = []
    buses = storage.all(Bus)
    for bus in buses.values():
        data.append(bus.to_dict()) 
    if request.method == 'POST':
        data = request.form
        routes = storage.all(Route).values()
        plate_nos = [route.plate_no for route in routes]
        side_nos = [route.side_no for route in routes]
        departure = [route.depcity for route in routes]
        desparture = [route.descity for route in routes]
        dates = [route.date for route in routes]
        bus_ids = [route.bus_id for route in routes]
        print(data)
        descity = data.get('descity')
        depcity = data.get('depcity')
        kilometer = data.get('kilometer')
        plate_no = data.get('plate_no')
        side_no = data.get('side_no')
        price = data.get('price')
        bus_id = data.get('bus_id')
        date = data.get('date')
        if bus_id in bus_ids:
            flash("The bus is reserved for another route", category="error")
        elif depcity == descity:
            flash("Departure and Desparture the Same !!!")
        else:
            info = {"depcity": depcity, "side_no": side_no, "price": price, "date": date, "descity": descity, "kilometer": kilometer, "plate_no": plate_no, "bus_id": bus_id}
            new_account = Route(**info)
            new_account.save()
            flash("Route successfully submitted!", category='success')
            return redirect(url_for('views.route'))
    return render_template('route.html',des=des, data=data, user=current_user)

@views.route('/city', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/city')
def city():
    if request.method == 'POST':
        data = request.form
        cities= storage.all(City).values()
        departure = [citiy.depcity for citiy in cities]
        depcity = data.get('depcity')
        if depcity in departure:
            flash("The depcity is existed!", category="error")
        else:
            info = {"depcity": depcity}
            new_account = City(**info)
            new_account.save()
            flash("City successfully registered!", category='success')
            return redirect(url_for('views.city'))
    return render_template('city.html')
@views.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        users = storage.all(Admin).values()
        usernames = [user.username for user in users]
        emails = [user.email for user in users]
        phones = [user.phone for user in users]
        data = request.form
        print(data)
        email = data.get('email')
        fname = data.get('fname')
        lname = data.get('lname')
        password = data.get('password')
        phone = data.get('phone')
        gender = data.get('gender')
        username = data.get('username')
        if username in usernames:
            flash("Username already exists", category="error")
        elif email in emails:
            flash("Email address already exists", category='error')
        elif len(password) < 6 or len(password) > 15:
            flash("Password must be 6 - 15 characters length",
                  category='error')
        elif len(phone) != 10:
            flash("Please insert a valid phone number", category='error')
        elif phone in phones:
            flash("Phone number already exists", category='error')
        else:
            info = {"fname": fname, "lname": lname,
                    "username": username, "password": password, "phone": phone, "gender": gender,
                    "email": email
                    }
            new_account = Admin(**info)
            new_account.save()
            login_user(new_account, remember=True)
            return redirect(url_for('views.home'))
            return "User Registor Correctlly!"
    return render_template("admin.html", user=current_user)
@views.route('/registor', methods=['GET', 'POST'], strict_slashes=False)
@views.route('/')
def registor():
    if request.method == 'POST':
        users = storage.all(User).values()
        usernames = [user.username for user in users]
        emails = [user.email for user in users]
        phones = [user.phone for user in users]
        data = request.form
        print(data)
        email = data.get('email')
        fname = data.get('fname')
        lname = data.get('lname')
        password = data.get('password')
        phone = data.get('phone')
        gender = data.get('gender')
        username = data.get('username')
        if username in usernames:
            flash("Username already exists", category="error")
        elif email in emails:
            flash("Email address already exists", category='error')
        elif phone in phones:
            flash("Phone number already exists", category='error')
        else:
            info = {"fname": fname, "lname": lname,
                    "username": username, "password": password, "phone": phone, "gender": gender,  
                    "email": email
                    }
            new_account = User(**info)
            new_account.save()
            login_user(new_account, remember=True)
        


        if request.form.get('name') and request.form.get('email'):
            flash('Registration successful!', 'success')
        else:
            flash('Error occurred during registration.', 'error')

        

            return redirect(url_for('views.registor'))
    return render_template("registor.html", user=current_user)    
@views.route('/ad')
@views.route('/')
def ad():
    return render_template('ad.html')
@views.route('/checkuser')
def checkuser():
    return render_template('checkuser.html')
@views.route('/get_user', methods=['GET', 'POST'])
def get_user():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email=?', (email,))
        users = cursor.fetchall()
        if users:
            for user in users:
                return render_template('userss.html', users=users)
        else:
            return render_template('checkuser.html')
    return render_template('checkuser.html')

@views.route('/get_route', methods=['GET', 'POST'])
def get_route():
    if request.method == 'POST':
        date = request.form['date']
        depcity = request.form['depcity']
        descity = request.form['descity']
        
        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM routes WHERE date = ? AND depcity = ? AND descity = ?", (date, depcity, descity))
        routes = c.fetchall()
        conn.close()
        
        if routes:
            return render_template('checkroot.html', routes=routes)
        else:
            return render_template('cheeckrout.html')
    return render_template('cheeckrout.html')

@views.route('/book', methods=['GET', 'POST'])
def book():
    if request.method == 'POST':
        date = request.form['date']
        depcity = request.form['depcity']
        descity = request.form['descity']

        # Check if user exists in database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM routes WHERE date = ? AND depcity = ? AND descity = ? ", (date, depcity, descity))
        routes = c.fetchall()
        conn.close()
        if routes:
            for route in routes:
                if isinstance(route, dict):  
                    depcity = route[5]
                    plate_no = route[3]
                    descity = route[4]
                    date = route[7]
            return render_template('roote.html', routes=routes, success="Has Route book your Ticket!! ")
        else:
            return render_template('cheeckroutee.html', error='Incorrect depcity or descity or date')
    return render_template('cheeckroutee.html')
@views.route('/Select', methods=['GET', 'POST'])
def Select():
    if request.method == 'POST':
        plate_no = request.form['plate_no']
        depcity = request.form['depcity']
        descity = request.form['descity']
        date = request.form['date']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(no_seat) FROM tickets WHERE depcity = ? AND descity = ? AND date = ? AND plate_no = ?', (depcity, descity, date, plate_no))
        data = cursor.fetchall()
        count = data[0]
        conn.close()
        count_str = str(count)
        count_str = count_str.strip('(),')

        

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(no_seat) FROM tickets WHERE depcity = ? AND descity = ? AND date = ? AND plate_no = ?', (depcity, descity, date, plate_no))
        data = cursor.fetchall()
        count = data[0]
        conn.close()
        count_str = str(count)
        count_str = count_str.strip('(),')
    


        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(no_seat) FROM tickets WHERE depcity = ? AND descity = ? AND date = ? AND plate_no = ?', (depcity, descity, date, plate_no))
        seatnumber = cursor.fetchone()
        conn.close()

        numcount = seatnumber[0]
        wenberkutr = str(int(numcount) + 1)


        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM routes WHERE depcity = ? AND descity = ? AND date = ? AND plate_no = ?", (depcity, descity, date, plate_no))
        routes = c.fetchall()
        conn.close()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT no_seats FROM buses WHERE plate_no = ?", (plate_no,))
        no_seat = c.fetchall()
        seat = no_seat[0]
        conn.close()
        seats = str(seat)
        seats = seats.strip('(),')
        seats = int(seats)
        count_str = int(count_str)
        kery = seats - count_str
        if routes:
            for route in routes:
                return render_template('ticket.html',kery=kery, wenberkutr=wenberkutr, routes=routes)
        else:
            return render_template('roote.html')
    return render_template('roote.html')
@views.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        # Get the current password and new password from the form
        current_password = request.form['password']
        new_password = request.form['new_password']
        # Logic for changing the user's password
        if check_password(current_password):
            change_password_in_database(new_password)
            return 'Password changed successfully'
        else:
            return 'Current password is incorrect'
    else:
        # Render the change password form
        return render_template('changepassword.html')

@views.route('/details')
def details():
    """"Details page for hospitals"""
    bus_id = request.args.get('id')
    bus = storage.get(Bus, bus_id)
    route_name = storage.get(Route, bus.route_id).name
    number_of_schedules = len(bus.schedules)
    return render_template('details.html',
                           user=current_user,
                           bus=bus,
                           route_name=route_name,
                           number_of_schedules=number_of_schedules)
"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')
"""


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists in the users table
        user_conn = sqlite3.connect('database.db')
        user_c = user_conn.cursor()
        user_c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = user_c.fetchone()
        user_conn.close()

        # Check if user exists in the admins table
        admin_conn = sqlite3.connect('database.db')
        admin_c = admin_conn.cursor()
        admin_c.execute("SELECT * FROM admins WHERE username = ? AND password = ?", (username, password))
        admin = admin_c.fetchone()
        admin_conn.close()

        if user:
            return redirect(url_for('profile'))
        elif admin:
            return redirect(url_for('ad'))
        else:
            return render_template('login.html', error='Invalid username or password')
    else:
        return render_template('login.html')

@views.route('/profile')
def profile():
    return render_template('profile.html', user=current_user)
    if __name__ == '__main__':
        app.run(debug=True)
