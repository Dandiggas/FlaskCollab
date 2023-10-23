#!/usr/bin/env bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj '/CN=localhost'
mv cert.pem certificate/cert.pem
mv key.pem certificate/key.pem