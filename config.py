import fdb

SECRET_KEY = 'chave_secreta_projeto_vendas'

def get_db_connection():
    try:
        conn = fdb.connect(
            dsn=r'C:\Users\Aluno\Desktop\Back_Hamb-main\BANCO.FDB',
            user='SYSDBA',
            password='sysdba',
            charset='UTF8',
            fb_library_name=r'C:\Program Files\Firebird\Firebird_3_0\fbclient.dll'
        )
        return conn
    except Exception as e:
        print(f"Erro ao conectar no banco: {e}")
        return None