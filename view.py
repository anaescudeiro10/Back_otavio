import datetime
import os
import re
import threading
import random
import jwt
from flask import jsonify, request
from main import app, get_db_connection
from funcao import (criptografar, checar_senha, enviando_email)

# Configuração de Pasta de Upload
UPLOAD_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], "usuarios")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def validar_conexao(con):
    if con is None:
        return False
    return True


# ---------------------------------------------------------
# 1. CRIAR USUÁRIO (Com código de 6 dígitos)
# ---------------------------------------------------------
@app.route('/criar_usuario', methods=['POST'])
def criar_usuario():
    con = get_db_connection()
    if not validar_conexao(con):
        return jsonify({'erro': 'Erro de conexão com o banco'}), 500

    cur = con.cursor()
    try:
        dados = request.form if request.form else request.json
        nome = dados.get('nome')
        email = dados.get('email')
        senha = dados.get('senha')
        tipo_nome = dados.get('tipo', 'cliente').lower()
        id_tipo = 1 if tipo_nome == 'admin' else 2

        if not nome or not email or not senha:
            return jsonify({'erro': 'Campos obrigatórios faltando.'}), 400

        # Gerar código de 6 dígitos aleatório
        codigo_confirmacao = str(random.randint(100000, 999999))

        # Inserir Usuário
        cur.execute("""
            INSERT INTO USUARIO (NOME, EMAIL, SENHA, ID_TIPO, TIPO_NOME, CONTA_CONFIRMADA, BLOQUEADO, TENTATIVAS_LOGIN)
            VALUES (?, ?, ?, ?, ?, False, False, 0)
        """, (nome, email, criptografar(senha), id_tipo, tipo_nome))

        # Pegar o ID do usuário que acabou de ser criado (Sintaxe compatível com Firebird)
        cur.execute("SELECT MAX(ID_USUARIO) FROM USUARIO")
        id_usuario = cur.fetchone()[0]

        # Salvar código na tabela CODIGOS
        cur.execute("""
            INSERT INTO CODIGOS (ID_USUARIO, CODIGO, TIPO, UTILIZADO) 
            VALUES (?, ?, 'CONFIRMACAO', False)
        """, (id_usuario, codigo_confirmacao))

        con.commit()

        # Enviar e-mail em segundo plano
        threading.Thread(target=enviando_email, args=(
            email, "Confirmação de Conta", f"Seu código de ativação é: {codigo_confirmacao}"
        )).start()

        return jsonify({"mensagem": "Usuário criado! Verifique seu e-mail.", "id": id_usuario}), 201
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        con.close()


@app.route('/confirmar_codigo', methods=['POST'])
def confirmar_codigo():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        # Pega dados tanto de JSON quanto de Form/Raw
        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')
        codigo = dados.get('codigo')

        if not email or not codigo:
            return jsonify({'erro': 'E-mail e código são obrigatórios.'}), 400

        # 1. Buscar usuário pelo email
        cur.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({'erro': 'Usuário não encontrado.'}), 404

        id_user = user[0]

        # 2. Verificar se o código existe, é do tipo CONFIRMACAO e não foi usado
        # Importante: No seu banco a tabela chama-se CODIGOS
        cur.execute("""
            SELECT ID FROM CODIGOS 
            WHERE ID_USUARIO = ? AND CODIGO = ? AND UTILIZADO = False AND TIPO = 'CONFIRMACAO'
        """, (id_user, codigo))

        cod_res = cur.fetchone()

        if cod_res:
            id_registro_codigo = cod_res[0]

            # 3. Atualizar status do usuário
            cur.execute("UPDATE USUARIO SET CONTA_CONFIRMADA = True WHERE ID_USUARIO = ?", (id_user,))

            # 4. Marcar o código como utilizado
            cur.execute("UPDATE CODIGOS SET UTILIZADO = True WHERE ID = ?", (id_registro_codigo,))

            con.commit()
            return jsonify({"mensagem": "Conta ativada com sucesso!"}), 200

        return jsonify({"erro": "Código inválido ou já utilizado."}), 400

    except Exception as e:
        if con:
            con.rollback()
        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500
    finally:
        if con:
            con.close()


@app.route('/login_usuario', methods=['POST'])
def login_usuario():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        # Tenta capturar JSON. Se falhar ou vier vazio, tenta capturar Form-Data/Form-Urlencoded
        dados = request.get_json(silent=True) or request.form

        if not dados:
            return jsonify({'erro': 'Nenhum dado enviado.'}), 400

        email = dados.get('email')
        senha_enviada = dados.get('senha')

        # Validação de campos vazios
        if not email or not senha_enviada:
            return jsonify({'erro': 'E-mail e senha são obrigatórios.'}), 400

        # Busca o usuário no banco (Usando seus nomes de colunas do SQL)
        cur.execute("""
            SELECT ID_USUARIO, SENHA, NOME, TIPO_NOME, CONTA_CONFIRMADA, BLOQUEADO, ATIVO 
            FROM USUARIO 
            WHERE EMAIL = ?
        """, (email,))

        usuario = cur.fetchone()

        # 1. Se o e-mail não existir no banco, dá erro imediatamente
        if not usuario:
            return jsonify({'erro': 'Usuário não encontrado ou e-mail incorreto.'}), 401

        id_u, hash_db, nome, tipo, conf, block, ativo = usuario

        # 2. Verificações de segurança de conta
        if not ativo:
            return jsonify({'erro': 'Esta conta está desativada.'}), 403

        if block:
            return jsonify({'erro': 'Conta bloqueada.'}), 403

        if not conf:
            return jsonify({'erro': 'E-mail não confirmado. Ative sua conta primeiro.'}), 403

        # 3. Verificação da Senha
        if checar_senha(senha_enviada, hash_db):
            # Gera o Token JWT
            token = jwt.encode({
                'id': id_u,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'token': token,
                'nome': nome,
                'tipo': tipo,
                'mensagem': 'Login realizado com sucesso!'
            }), 200

        # Senha errada
        return jsonify({'erro': 'Senha incorreta.'}), 401

    except Exception as e:
        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500
    finally:
        if con:
            con.close()

# ---------------------------------------------------------
# 3. LISTAR USUÁRIOS
# ---------------------------------------------------------
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME, CONTA_CONFIRMADA FROM USUARIO")
        rows = cur.fetchall()
        res = [{'id': r[0], 'nome': r[1], 'email': r[2], 'tipo': r[3], 'confirmado': r[4]} for r in rows]
        return jsonify(res), 200
    finally:
        con.close()


import re


@app.route('/editar_usuario/<int:id>', methods=['PUT'])
def editar_usuario(id):
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        dados = request.get_json(silent=True) or request.form
        nome = dados.get('nome')
        nova_senha = dados.get('senha')

        # 1. VALIDAÇÃO DO NOME (Não permite branco)
        if nome is not None:
            nome_limpo = nome.strip()
            if not nome_limpo:
                return jsonify({"erro": "O nome não pode estar em branco."}), 400
            cur.execute("UPDATE USUARIO SET NOME = ? WHERE ID_USUARIO = ?", (nome_limpo, id))

        # 2. VALIDAÇÃO DE SENHA (Forte + Diferente da anterior)
        if nova_senha:
            # Regras de Senha Forte
            if (len(nova_senha) < 8 or
                    not re.search(r"[a-z]", nova_senha) or
                    not re.search(r"[A-Z]", nova_senha) or
                    not re.search(r"[0-9]", nova_senha)):
                return jsonify(
                    {"erro": "A senha deve ter pelo menos 8 caracteres, com maiúsculas, minúsculas e números."}), 400

            # --- VERIFICAÇÃO DE SENHA ANTERIOR ---
            cur.execute("SELECT SENHA FROM USUARIO WHERE ID_USUARIO = ?", (id,))
            resultado = cur.fetchone()

            if resultado:
                senha_hash_atual = resultado[0]
                # Se a nova senha (texto puro) for igual ao hash atual...
                if checar_senha(nova_senha, senha_hash_atual):
                    return jsonify({"erro": "A nova senha não pode ser igual à senha atual."}), 400
            # -------------------------------------

            # Criptografa e atualiza
            senha_final_hash = criptografar(nova_senha)
            cur.execute("UPDATE USUARIO SET SENHA = ? WHERE ID_USUARIO = ?", (senha_final_hash, id))

        # 3. TRATAMENTO DA FOTO
        foto = request.files.get('foto')
        if foto:
            foto.save(os.path.join(UPLOAD_FOLDER, f"perfil_{id}.jpg"))

        con.commit()
        return jsonify({"mensagem": "Dados atualizados com sucesso"}), 200

    except Exception as e:
        if con: con.rollback()
        return jsonify({"erro": str(e)}), 500
    finally:
        if con: con.close()

# ---------------------------------------------------------
# 5. EXCLUIR USUÁRIO
# ---------------------------------------------------------
@app.route('/excluir_usuario/<int:id>', methods=['DELETE'])
def excluir_usuario(id):
    con = get_db_connection()
    if not validar_conexao(con): return jsonify({'erro': 'Banco offline'}), 500
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM USUARIO WHERE ID_USUARIO = ?", (id,))
        con.commit()
        return jsonify({"mensagem": "Usuário removido"}), 200
    except Exception as e:
        con.rollback()
        return jsonify({"erro": str(e)}), 500
    finally:
        con.close()


@app.route('/solicitar_recuperacao', methods=['POST'])
def solicitar_recuperacao():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        # Aceita JSON ou Formulário
        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')

        if not email:
            return jsonify({'erro': 'O e-mail é obrigatório.'}), 400

        # 1. Verificar se o usuário existe
        cur.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
        user = cur.fetchone()

        if user:
            id_usuario = user[0]

            # 2. Gerar código de 6 dígitos aleatório
            codigo = str(random.randint(100000, 999999))

            # 3. Definir expiração (ex: 15 minutos a partir de agora)
            expiracao = datetime.datetime.now() + datetime.timedelta(minutes=15)

            # 4. Inserir na tabela RECUPERAR_SENHA conforme seu SQL
            cur.execute("""
                INSERT INTO RECUPERAR_SENHA (ID_USUARIO, CODIGO, EXPIRACAO, UTILIZADO) 
                VALUES (?, ?, ?, False)
            """, (id_usuario, codigo, expiracao))

            con.commit()

            # 5. Enviar o e-mail de forma assíncrona (Thread) para não travar a resposta
            threading.Thread(target=enviando_email, args=(
                email,
                "Recuperação de Senha",
                f"Seu código de recuperação é: {codigo}. Ele expira em 15 minutos."
            )).start()

            return jsonify(
                {"mensagem": "Se o e-mail informado estiver cadastrado, você receberá um código de 6 dígitos."}), 200

        # Por segurança, mesmo que o e-mail não exista, damos a mesma resposta para evitar varredura de e-mails
        return jsonify(
            {"mensagem": "Você receberá um código de 6 dígitos para criar uma nova senha."}), 200

    except Exception as e:
        if con: con.rollback()
        return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
    finally:
        if con: con.close()



# ---------------------------------------------------------
# 6. REDEFINIR SENHA (Nova Senha e Confirmar Senha)
# ---------------------------------------------------------
@app.route('/redefinir_senha', methods=['POST'])
def redefinir_senha():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        # Resolve o Erro 415: Aceita JSON ou Form-data do Postman
        dados = request.get_json(silent=True) or request.form

        codigo = dados.get('codigo')
        nova_senha = dados.get('nova_senha')
        confirmar_senha = dados.get('confirmar_senha')

        # 1. Validações básicas de preenchimento
        if not all([codigo, nova_senha, confirmar_senha]):
            return jsonify({"erro": "Todos os campos (codigo, nova_senha, confirmar_senha) são obrigatórios."}), 400

        if nova_senha != confirmar_senha:
            return jsonify({"erro": "As senhas não coincidem."}), 400

        # 2. Validação de Senha Forte
        if (len(nova_senha) < 8 or
                not re.search(r"[a-z]", nova_senha) or
                not re.search(r"[A-Z]", nova_senha) or
                not re.search(r"[0-9]", nova_senha)):
            return jsonify({
                               "erro": "A nova senha deve ter no mínimo 8 caracteres, incluindo letras maiúsculas, minúsculas e números."}), 400

        # 3. Verifica se o código é válido e pertence a um usuário
        cur.execute("""
            SELECT ID_USUARIO FROM RECUPERAR_SENHA 
            WHERE CODIGO = ? AND UTILIZADO = False AND EXPIRACAO > CURRENT_TIMESTAMP
        """, (codigo,))
        res = cur.fetchone()

        if not res:
            return jsonify({"erro": "Código inválido, já utilizado ou expirado."}), 400

        id_u = res[0]

        # 4. Verificação de reuso: Não permite a senha que já está no banco
        cur.execute("SELECT SENHA FROM USUARIO WHERE ID_USUARIO = ?", (id_u,))
        senha_hash_atual = cur.fetchone()[0]

        if checar_senha(nova_senha, senha_hash_atual):
            return jsonify({"erro": "A nova senha não pode ser igual à senha antiga."}), 400

        # 5. Atualiza a senha e invalida o código usado
        cur.execute("UPDATE USUARIO SET SENHA = ? WHERE ID_USUARIO = ?", (criptografar(nova_senha), id_u))
        cur.execute("UPDATE RECUPERAR_SENHA SET UTILIZADO = True WHERE CODIGO = ?", (codigo,))

        con.commit()
        return jsonify({"mensagem": "Senha alterada com sucesso!"}), 200

    except Exception as e:
        if con: con.rollback()
        return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
    finally:
        if con: con.close()


@app.route('/buscar_usuario', methods=['GET'])
def buscar_usuario():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro de conexão com o banco de dados.'}), 500

    cur = con.cursor()
    try:
        # Pega o termo da URL
        termo = request.args.get('termo', '').strip()

        # Se o usuário não digitar nada, em vez de erro, retornamos todos (ou uma lista vazia)
        if not termo:
            cur.execute("SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME FROM USUARIO")
        elif termo.isdigit():
            # Busca por ID exato
            cur.execute("""
                SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME 
                FROM USUARIO WHERE ID_USUARIO = ?
            """, (termo,))
        else:
            # Busca por Nome ou Email usando LIKE (formatado para o banco)
            # O UPPER garante que não haja erro entre maiúsculas e minúsculas
            filtro = f"%{termo.upper()}%"
            cur.execute("""
                SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME 
                FROM USUARIO 
                WHERE UPPER(NOME) LIKE ? OR UPPER(EMAIL) LIKE ?
            """, (filtro, filtro))

        rows = cur.fetchall()

        # Converte para JSON
        resultados = []
        for r in rows:
            resultados.append({
                'id': r[0],
                'nome': r[1],
                'email': r[2],
                'tipo': r[3]
            })

        return jsonify(resultados), 200

    except Exception as e:
        return jsonify({'erro': f'Erro no banco: {str(e)}'}), 500
    finally:
        if con:
            con.close()



@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"mensagem": "Logout realizado. Delete o token no cliente."}), 200