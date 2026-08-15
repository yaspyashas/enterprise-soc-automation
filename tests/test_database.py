from database.db_connection import get_connection


def test_postgresql_connection():

    connection = get_connection()

    try:
        assert connection is not None
        assert not connection.closed

    finally:
        connection.close()

    assert connection.closed


def test_connected_database_name():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT current_database();"
        )

        database_name = cursor.fetchone()[0]

        assert database_name == "soc_automation"

        cursor.close()

    finally:
        connection.close()