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

### JWT Token
The server can generate a JWT token for authenticated users, it is signed using HMAC with symmetric encryption (a secret key kept on the server), with SHA.256 as hashing algorithm. When the user tries to call sensitive endpoints the jwt token is included as an Authorization Bearer token and it is verified that when the signature is rehashes from header + payload using HMAC and the secret key, the calculate signature is the same as the bearer token signature.

### Frontend (TODO)
App should have a frontend to interact with the authorization endpoints.

### Database (TODO)
Currently the app uses an in-memory dictionary for storing data, this should be switched to a proper database (like SQLite). This will persist users after a server crash.

### Password Reset (TODO)
A password rest function that involves involves generating a unique link or code, emailing it to the user, and then allowing the user to reset their password using that code.

### Additional User Data + User Profile (TODO)
Allows users to update their profile info after they log in. Enables changing password, email, or other personal info.

### Email Confirmation (TODO)
Implements an email confirmation step when a user registers in order to reduce fake sign-ups.

### Rate Limiting (TODO)
Rate limiting to sensitive routes like /login to prevent brute force attacks.

### Logout (TODO)
A logout mechanism. Since JWTs are stateless this is accomplished by maintaining a blacklist of tokens that should no longer be valid.

### Role-Based Authorization (TODO)
Extends the authorization to not just check if a user is authenticated, but also check for specific roles or permissions.

### Refresh Tokens (TOOD)
Short-lived JWTs are used along with refresh tokens when they expire are used rather than long-life JWTs.

### OAuth (TODO)
OAuth-based authentication is used so that users can log in using Google, Facebook, or other providers.


### Logging and Monitoring (TODO)
Keeps track of failed login attempts, suspicious activities, and other security-related events.

### API Protection (TODO)
TBD but intention to use additional mechanism to protect API, like API keys, OAuth scopes, etc.

### CORS (TODO)
Once both a front-end app and a back-end API is served from different domains or ports, CORS is to be implemented and configured so that only trusted domains can make requests to the API.

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