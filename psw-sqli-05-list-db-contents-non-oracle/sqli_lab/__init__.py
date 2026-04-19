"""
Register PyMySQL as the MySQLdb implementation so Django's mysql
backend can talk to the database without pulling in native build
tools for mysqlclient.
"""

import pymysql

pymysql.install_as_MySQLdb()
