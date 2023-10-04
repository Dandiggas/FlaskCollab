#!/usr/bin/env bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=US/ST=California/L=San Francisco/O=Company Name/OU=Org/CN=www.example.com"
mv cert.pem certificate/cert.pem
mv key.pem certificate/key.pem