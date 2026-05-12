import fdb
import config

def conectar():

    con = fdb.connect(
        host=config.Config.DB_HOST,
        database=config.Config.DB_PATH,
        user=config.Config.DB_USER,
        password=config.Config.DB_PASSWORD,
        charset="UTF8"
    )

    return con