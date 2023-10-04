# (Don't) roll your own auth

This repo holds a toy implementation that demonstrates the basics of how an authentication system can be setup to hold user credentials and authenticate users. It's not meant to be used in production, but rather as a learning tool for the authors and others who are interested in learning about authentication systems.

## Features

The authentication system is implemented as a simple flask app, serving endpoints for:
- Registering users
- Authenticating users

### Hashed passwords
The server allows registering new users and authenticating existing users. The passwords are hashed using the SCrypt algorithm, and the hashes are stored in memory. When a user authenticates, the provided password is hashed and compared to the stored hash.

### Salting
Prior to hashing the provided password, a random salt is generated and appended to it, to counteract rainbow table attacks.

### HTTPS
The backend is setup to serve its endpoins over HTTPS. The HTTPS certificate is self-signed rather than provided by a Certificate Authority, hence any user that wants to interact with the endpoints need to add the certificate to their trust store.

### JWT Token (TODO)
The server can generate a JWT token for authenticated users with defined roles and expiration. The token is signed with a secret key, and can be used by the client to authenticate future requests.

## Prerequisites

* Python 3.6+
* Flask
* Virtualenv

## Install and run
To run the application, do the following:

Activate the virtual environment:
```bash
source venv/bin/activate
```

Run the flask app:
```bash
flask run
```