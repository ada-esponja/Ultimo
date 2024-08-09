from bson import ObjectId
from flask import Flask, render_template, request, flash, redirect, url_for, session, Blueprint
from pymongo import MongoClient
from pymongo.errors import PyMongoError
#from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
import hashlib
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
def crear_app():
    app = Flask(__name__, static_folder="static")

    client = MongoClient("mongodb+srv://23301788:Elchachito34&@adex344.tder1t3.mongodb.net/")
    db = client['Practica1']
    records_collection = db['archivos_criticos']

    def conectar_db(uri):
        try:
            conexion = MongoClient(uri)
            return conexion
        except PyMongoError as e:
            print(f"Error de conexión: {e}")
            return None

    def registrar_usuario(coleccion, nombre, telefono, email, hashed_password):#llegan nuestros parametros
        datos = { #creamos nuestro diccionario para insertarlo en nuestra coleccion
            "nombre": nombre,
            "telefono": telefono,
            "email": email,
            "contrasena": hashed_password
        }
        coleccion.insert_one(datos)#usamos el metodo de insertar del modulo pymongo
        return render_template("create_record.html")

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/registro', methods=['GET', 'POST'])
    def registro():
        error = None  # aqui es nuestra variable para almacenar el mensaje de error

        if request.method == 'POST':
            nombre = request.form['nombre'] #traemos nuestros datos de nuestro formulario
            telefono = request.form['telefono']
            email = request.form['email']
            contrasena = request.form['contrasena']
            hashed_password = generate_password_hash(contrasena, method='pbkdf2:sha256') #guardamos en la variable la contraseña hasheada

            uri = "mongodb+srv://23301788:Elchachito34&@adex344.tder1t3.mongodb.net/"
            nombre_bd = "Practica1"
            nombre_coleccion = "datos"

            conexion = conectar_db(uri) #llamamos a la funcion conectar_db para establecer la conexion a mongo

            if conexion:
                db = conexion[nombre_bd]#obtenemos el nombre de la BD
                coleccion = db[nombre_coleccion]
                ver = coleccion.find_one({"email": email})#buscamos en la coleccion el email pa ver si ya existe una cuenta con este
                if ver:
                    error = 'Ya existe una cuenta registrada con este email.'
                else:
                    mensaje = registrar_usuario(coleccion, nombre, telefono, email, hashed_password)#llamamamos a nuestra funcion y se llevara estas variables
                    return mensaje #retorna nuestra informacion
            else:
                error = "Error de conexión a la Base de datos."

        return render_template('registro.html', error=error)#renderiza y pasa el mensaje de error al html


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':

            contrasena = request.form['contrasena']
            email = request.form['email']

            uri = "mongodb+srv://23301788:Elchachito34&@adex344.tder1t3.mongodb.net/"
            nombre_bd = "Practica1"
            nombre_coleccion = "datos"

            conexion = conectar_db(uri)
            if conexion is None:
                return ('Error de conexión a la base de datos.')
                return redirect(url_for('login'))

            db = conexion[nombre_bd]
            coleccion = db[nombre_coleccion]

            user_data = coleccion.find_one({"email": email})#buscamos el email en nuestra coleccion

            if user_data and check_password_hash(user_data['contrasena'], contrasena):#si el email se encuentra ahora comparamos la contra hash y l aingresada por el user
                return render_template("create_record.html")
            else:
                error = 'Usuario o contraseña incorrecta.'

                return render_template('login.html', error=error)

    @app.route('/iniciar', methods=['GET', 'POST'])
    def iniciar():
            return render_template('login.html')



    @app.route('/create_record', methods=['GET', 'POST'])
    def create_record():


         if request.method == 'POST':
            file_name = request.form['fileName']
            file_content = request.form['fileContent']
            file_bruto = request.form['fileContent']
            encryption_algorithm = request.form['encryptionAlgorithm']
            encryption_date = datetime.utcnow()

            # Validaciones en el servidor
            if not all([file_name, file_content, encryption_algorithm]):
                flash('Todos los campos son obligatorios.')
                return redirect(url_for('create_record'))
            # Encriptamos con el algoritmo sleccionado
            if encryption_algorithm == 'SHA128':
                encrypted_data = hashlib.sha1(file_content.encode()).hexdigest()[:32]
            elif encryption_algorithm == 'SHA256':
                encrypted_data = hashlib.sha256(file_content.encode()).hexdigest()
            elif encryption_algorithm == 'SHA512':
                encrypted_data = hashlib.sha512(file_content.encode()).hexdigest()
            else:
                flash('Algoritmo de cifrado no válido.')
                return redirect(url_for('create_record'))

            # Crear el registro
            record = {
                'file_name': file_name,
                'file_content': encrypted_data,
                'file_bruto' : file_bruto,
                'original_hash': encrypted_data,
                'encryption_algorithm': encryption_algorithm,
                'encryption_date': encryption_date
            }

            try:
                records_collection.insert_one(record)
                return render_template("exito.html")
            except PyMongoError as e:
                flash(f'Error al registrar el archivo crítico: {e}')



            return render_template('create_record.html')

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        return render_template('index.html')

    @app.route('/gestion', methods=['GET', 'POST'])
    def gestion():
        return render_template('gestionar_archivo.html')

    @app.route('/regresar')
    def regresar():
        return render_template('create_record.html')

    @app.route('/gestionar_archivo', methods=['GET', 'POST'])
    def gestionar_archivo():
        client = MongoClient("mongodb+srv://23301788:Elchachito34&@adex344.tder1t3.mongodb.net/")
        db = client['Practica1']
        records_collection = db['archivos_criticos']


        respuesta_consulta = records_collection.find({})#usamos las llaves para recuperar todos los documentos
        respuesta_lista = list(respuesta_consulta)#lo convierte en lista

        return render_template('gestionar_archivo.html', archivos = respuesta_lista)#pasamos la lista a traves de la v archivos

    @app.route('/modificar', methods=['POST'])
    def modificar_archivo():
        file_id = request.form['id']#obtenemos el id del archivo guardado en mongo mjmmmm xd
        file_name = request.form['fileName']
        file_content = request.form['fileContent']
        encryption_algorithm = request.form['encryptionAlgorithm']

        # Encriptar el contenido según el algoritmo seleccionado
        if encryption_algorithm == 'SHA128':
            encrypted_data = hashlib.sha1(file_content.encode()).hexdigest()[:32]
        elif encryption_algorithm == 'SHA256':
            encrypted_data = hashlib.sha256(file_content.encode()).hexdigest()
        elif encryption_algorithm == 'SHA512':
            encrypted_data = hashlib.sha512(file_content.encode()).hexdigest()
        else:
            flash('Algoritmo de cifrado no válido.')
            return redirect(url_for('gestionar_archivo'))


        try:
            records_collection.update_one(
                {'_id': ObjectId(file_id)},
                {'$set': {
                    'file_name': file_name,
                    'file_content': encrypted_data,  # Actualiza el contenido cifrado
                    'file_bruto': file_content,       # Actualiza el contenido en bruto
                    'original_hash': encrypted_data,  # Guarda el hash cifrado
                    'encryption_algorithm': encryption_algorithm,
                    'encryption_date': datetime.utcnow()
                }}
            )
            return redirect(url_for('gestionar_archivo'))
        except PyMongoError as e:
            flash(f'Error al modificar el archivo crítico: {e}')
            return redirect(url_for('gestionar_archivo'))



    @app.route('/eliminar', methods=['POST'])
    def eliminar_archivo():
        file_id = request.form['id']

        #elimina el archivo segun su id con el metodo delete buscandolo en la coleccion
        records_collection.delete_one({'_id': ObjectId(file_id)})#convertimos el id en objeto ya que es una cadena

        return redirect(url_for('gestionar_archivo'))

    return app
if __name__ == '__main__':
    app = crear_app()
   # app.run(host='localhost', port=3000, debug=True)