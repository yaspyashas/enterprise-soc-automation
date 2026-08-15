import psycopg2


DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "soc_automation",
    "user": "postgres",
    "password": "9900706696"
}


def get_connection():

    return psycopg2.connect(
        **DB_CONFIG
    )