import sqlite3

sqlite3.connect('lethal_scanner.db') #connect or create the relational database

# this is what moves around database and finds out what we need 
cursor= db.cursor()