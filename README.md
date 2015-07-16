# pyradiusd
Simple RADIUS server suitable for development purposes

It uses standard django.contrib.auth module.
Send accept if user can be autenticated in django by supplied password.
Else send reject.

django_pyradiud.py uses standard Django config for work and auth.User to autenticate.

pyradiud.py is very simply server what uses username/password pairs stored directly in its code.

Both should be run standalone
./pyradiud.py
or 
python pyradiud.py

Idea from https://github.com/jamiesun/PyRadius
