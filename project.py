#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect,jsonify, url_for, flash, get_flashed_messages, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, Restaurant, MenuItem, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import random, string, httplib2, json, requests


app = Flask(__name__)
app.secret_key = 'super_secret_key'

DB = 'sqlite:///restaurantmenu_users.db'

# Connect to Database and create database session
engine = create_engine(DB)
Base.metadata.bind = engine

session = scoped_session(sessionmaker(bind=engine))

CLIENT_ID = json.loads(open('client_secret.json', 'r').read())['web']['client_id']
APP_NAME = 'Restaurant Menu App'


def create_user(login_session):
    session.add(User(name=login_session.get('username'),
                     email=login_session.get('email'),
                     picture=login_session.get('picture')))

    session.commit()
    user_created = session.query(User).filter_by(email=login_session.get('email')).one()
    return user_created.id


def get_user_info(user_id):
    return session.query(User).filter_by(id=user_id).one()


def get_user_id(user_email):
    try:
        return session.query(User).filter_by(email=user_email).one().id
    except Exception as e:
        return None

def not_logged_in():
    return 'username' not in login_session


# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    return jsonify(Menu_Item=session.query(MenuItem).filter_by(id=menu_id).one().serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))

    if not_logged_in():
        return render_template('publicrestaurants.html.html', restaurants=restaurants)

    return render_template('restaurants.html', restaurants = restaurants)


# Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def new_restaurant():
    if not_logged_in():
        return redirect('/login')

    if request.method == 'POST':
        new = Restaurant(
            name=request.form['name'],
            user_id=login_session.get('user_id'))
        session.add(new)
        flash('New Restaurant %s Successfully Created' %new.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


# Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
    if not_logged_in():
        return redirect('/login')

    editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant = editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
    if not_logged_in():
        return redirect('/login')

    restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
    else:
        return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)


# Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    creator = get_user_info(restaurant.user_id)
    if not_logged_in() or creator.id != login_session.get('user_id'):
        return render_template('publicmenu.html', items=items, restaurant=restaurant, creator=creator)
    return render_template('menu.html',
                           items=items,
                           restaurant=restaurant,
                           creator=creator)


# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
    if not_logged_in():
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'],
                           description = request.form['description'],
                           price=request.form['price'],
                           course = request.form['course'],
                           restaurant_id = restaurant_id,
                           user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)


# Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    if not_logged_in():
        return redirect('/login')

    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if not_logged_in():
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one() 
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)


# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=login_session['state'])


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        # Different state data
        return create_response('Invalid state parameter')

    code = request.data

    try:
        # Upgrade the authorization code into the credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError as fee:
        return create_response('Failed to updgrade')

    access_token = credentials.access_token
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        return create_response(result.get('error'), 500)

    # Verify that the access_token is used for the intended user
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        return create_response('Token user id does not match giver user id')

    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        return create_response('Token client id does not match app´s')

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and stored_gplus_id == gplus_id:
        return create_response('Current user is already connected', 200)

    # store data on the session for later use
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {
        'access_token': access_token,
        'alt': 'json'
    }
    answer = requests.get(user_info_url, params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exists at the database, if not create a new one
    user_id = get_user_id(login_session.get('email'))
    if not user_id:
        user_id = create_user(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;
    -moz-border-radius: 150px;">"""""

    flash("you are now logged in as {}".format(login_session['username']))

    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        return create_response('Current user not even connected')

    username = login_session.get('username')

    print('Access token is: {}'.format(access_token))
    print('Username is: {}'.format(username))

    url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)
    print(url)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is {}'.format(result))

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['email']

        return create_response('Successfully disconnected', 200)
    else:
        return create_response('Failed to revoke the token for the user {}'.format(username), 400)


def create_response(msg, code=401):
    resp = make_response(json.dumps(msg), code)
    resp.headers['Content-Type'] = 'application/json'
    return resp


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
