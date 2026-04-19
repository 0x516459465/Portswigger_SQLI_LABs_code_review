"""
Register PyMySQL as the MySQLdb implementation so Django's mysql
backend can talk to the database without pulling in native build
tools for mysqlclient. The shim must run before Django imports the
database backend.
"""

import pymysql

pymysql.install_as_MySQLdb()
