#app.py
import os
import secrets
import hashlib
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="API Monitoreo Materno-Fetal")

# Configurar CORS para permitir peticiones desde la interfaz HTML
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/favicon.ico")
def favicon():
    return FileResponse("static/icon-193.png", media_type="image/png")

# --- CONFIGURACIÓN DE BASE DE DATOS (LOCAL O CLOUD) ---
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    try:
        if DATABASE_URL:
            # Si estamos en Render, se conecta automáticamente a la nube usando la variable de entorno
            return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        else:
            # Configuración local por si deseas ejecutarlo en tu computadora de prueba
            db_config = {
                "host": "localhost",
                "database": "MONITOREO_EMBARAZADAS",
                "user": "postgres",
                "password": "123456",
                "port": "5432"
            }
            return psycopg2.connect(**db_config, cursor_factory=RealDictCursor)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error conectando a PostgreSQL: {str(e)}")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def generate_token() -> str:
    return secrets.token_hex(24) # Genera un token alfanumérico único

COLS = {
    'fc_materna': 'frecuencia_cardiaca_materna',
    'fc_fetal': 'frecuencia_cardiaca_fetal',
    'presion_sistolica': 'presion_sistolica',
    'presion_diastolica': 'presion_diastolica',
}

def auth(cur, token, roles):
    cur.execute("SELECT id_usuario, rol FROM usuario_sistema WHERE token_sesion = %s;", (token,))
    u = cur.fetchone()
    if not u or u['rol'] not in roles:
        raise HTTPException(status_code=403, detail="Acceso no autorizado.")
    return u

def get_offsets(cur):
    cur.execute("SELECT DISTINCT ON (sensor) sensor, offset_lineal FROM calibracion_sensor ORDER BY sensor, fecha DESC;")
    return {r['sensor']: float(r['offset_lineal']) for r in cur.fetchall()}

def corregir(lectura, offsets):
    if not lectura:
        return None
    l = dict(lectura)
    for s, col in COLS.items():
        l[col] = round(l[col] + offsets.get(s, 0))
    return l

class Calibracion(BaseModel):
    sensor: str
    valor_patron: float
    valor_leido: float

# --- MODELOS DE DATOS ---
class RegistroUsuario(BaseModel):
    nombre: str
    primer_apellido: str
    segundo_apellido: Optional[str] = ""
    carnet_identidad: str
    celular: str
    usuario: str
    contrasena: str
    rol: str # Administrador, Operador, Servicio Técnico

class LoginUsuario(BaseModel):
    usuario: str
    contrasena: str

class RegistroPaciente(BaseModel):
    nombre: str
    primer_apellido: str
    segundo_apellido: Optional[str] = ""
    carnet_identidad: str
    fecha_nacimiento: str
    celular: str
    trimestre: int
    semanas_gestacion: int

# --- ENDPOINTS / RUTAS DE LA API ---

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/api/check-admin")
def check_admin():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM usuario_sistema WHERE rol = 'Administrador';")
    count = cur.fetchone()['count']
    cur.close()
    conn.close()
    return {"has_admin": count > 0}

@app.post("/api/register")
def register_user(data: RegistroUsuario, token: Optional[str] = None):
    conn = get_db_connection()
    cur = conn.cursor()

    # Verificar si ya existe al menos un Administrador
    cur.execute("SELECT COUNT(*) FROM usuario_sistema WHERE rol = 'Administrador';")
    admin_count = cur.fetchone()['count']

    # Si ya hay un Admin, requerimos que la petición la haga un Admin válido
    if admin_count > 0:
        if not token:
            raise HTTPException(status_code=401, detail="Se requiere token de Administrador")
        cur.execute("SELECT rol FROM usuario_sistema WHERE token_sesion = %s;", (token,))
        user = cur.fetchone()
        if not user or user['rol'] != 'Administrador':
            raise HTTPException(status_code=403, detail="Solo un Administrador puede registrar nuevos usuarios")

    # Encriptar contraseña y guardar en PostgreSQL
    pass_hash = hash_password(data.contrasena)
    try:
        cur.execute("""
            INSERT INTO usuario_sistema 
            (nombre, primer_apellido, segundo_apellido, carnet_identidad, celular, usuario, contrasena_hash, rol)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id_usuario;
        """, (data.nombre, data.primer_apellido, data.segundo_apellido, data.carnet_identidad, data.celular, data.usuario, pass_hash, data.rol))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="El usuario o carnet ya se encuentra registrado.")
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": "Usuario registrado exitosamente."}

@app.post("/api/login")
def login(data: LoginUsuario):
    conn = get_db_connection()
    cur = conn.cursor()
    pass_hash = hash_password(data.contrasena)

    cur.execute("""
        SELECT id_usuario, nombre, primer_apellido, rol 
        FROM usuario_sistema 
        WHERE usuario = %s AND contrasena_hash = %s;
    """, (data.usuario, pass_hash))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")

    # Generar token alfanumérico en Python y guardarlo en la BD
    new_token = generate_token()
    cur.execute("UPDATE usuario_sistema SET token_sesion = %s WHERE id_usuario = %s;", (new_token, user['id_usuario']))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "ok",
        "token": new_token,
        "rol": user['rol'],
        "nombre": f"{user['nombre']} {user['primer_apellido']}"
    }

@app.get("/api/user-info")
def get_user_info(token: str = Query(...)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id_usuario, nombre, primer_apellido, rol FROM usuario_sistema WHERE token_sesion = %s;", (token,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")

    return user

@app.post("/api/paciente")
def registrar_paciente(data: RegistroPaciente, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    user = auth(cur, token, ['Operador'])   # solo Operador (id_operador_asignado es NOT NULL)
    try:
        cur.execute("""
            INSERT INTO paciente (nombre, primer_apellido, segundo_apellido, carnet_identidad, fecha_nacimiento,
                                  celular, trimestre, semanas_gestacion, id_operador_asignado)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);
        """, (data.nombre, data.primer_apellido, data.segundo_apellido, data.carnet_identidad,
              data.fecha_nacimiento, data.celular, data.trimestre, data.semanas_gestacion, user['id_usuario']))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error registrando paciente: {str(e)}")
    finally:
        cur.close(); conn.close()
    return {"status": "ok"}

@app.get("/api/pacientes")
def listar_pacientes(token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Administrador', 'Operador'])  # Técnico fuera
    sql = """SELECT id_paciente, nombre, primer_apellido, segundo_apellido, carnet_identidad,
                    trimestre, semanas_gestacion, id_operador_asignado FROM paciente"""
    if u['rol'] == 'Operador':
        cur.execute(sql + " WHERE id_operador_asignado = %s ORDER BY id_paciente DESC;", (u['id_usuario'],))
    else:
        cur.execute(sql + " ORDER BY id_paciente DESC;")
    data = cur.fetchall()
    cur.close(); conn.close()
    return data

@app.get("/api/paciente/buscar")
def buscar_paciente(ci: str, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Administrador', 'Operador'])
    q, params = "SELECT * FROM paciente WHERE carnet_identidad = %s", [ci]
    if u['rol'] == 'Operador':
        q += " AND id_operador_asignado = %s"; params.append(u['id_usuario'])
    cur.execute(q, params)
    p = cur.fetchone()
    if not p:
        cur.close(); conn.close()
        raise HTTPException(status_code=404, detail="Paciente no encontrada.")
    cur.execute("SELECT * FROM lecturas_monitoreo WHERE id_paciente = %s ORDER BY fecha_hora DESC LIMIT 50;", (p['id_paciente'],))
    lecturas = cur.fetchall()
    off = get_offsets(cur)
    cur.close(); conn.close()
    lecturas = [corregir(l, off) for l in lecturas]
    return {"paciente": p, "ultima": lecturas[0] if lecturas else None, "historial": lecturas}

# ---------- ADMINISTRADOR: datos y estadísticas (sin monitoreo en vivo) ----------
@app.get("/api/estadisticas")
def estadisticas(token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    auth(cur, token, ['Administrador'])
    cur.execute("""
        SELECT COUNT(DISTINCT id_paciente) AS pacientes_con_lecturas, COUNT(*) AS total_lecturas,
               ROUND(AVG(frecuencia_cardiaca_materna),1) AS fc_materna_prom,
               ROUND(AVG(frecuencia_cardiaca_fetal),1) AS fc_fetal_prom,
               ROUND(AVG(presion_sistolica),1) AS sistolica_prom,
               ROUND(AVG(presion_diastolica),1) AS diastolica_prom
        FROM lecturas_monitoreo;""")
    resumen = cur.fetchone()
    cur.execute("SELECT trimestre, COUNT(*) AS cantidad FROM paciente GROUP BY trimestre ORDER BY trimestre;")
    por_trim = cur.fetchall()
    cur.close(); conn.close()
    return {"resumen": resumen, "por_trimestre": por_trim}

@app.get("/api/lecturas")
def lecturas(token: str = Query(...), limit: int = 500):
    conn = get_db_connection(); cur = conn.cursor()
    auth(cur, token, ['Administrador'])
    cur.execute("SELECT * FROM lecturas_monitoreo ORDER BY fecha_hora DESC LIMIT %s;", (limit,))
    data = cur.fetchall()
    off = get_offsets(cur)
    cur.close(); conn.close()
    return [corregir(l, off) for l in data]

# ---------- SERVICIO TÉCNICO ----------
@app.post("/api/calibracion")
def guardar_calibracion(data: Calibracion, token: str = Query(...)):
    if data.sensor not in COLS:
        raise HTTPException(status_code=400, detail="Sensor inválido.")
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Servicio Técnico'])
    offset = data.valor_patron - data.valor_leido   # desfase lineal
    cur.execute("""INSERT INTO calibracion_sensor (sensor, valor_patron, valor_leido, offset_lineal, id_tecnico)
                   VALUES (%s,%s,%s,%s,%s);""",
                (data.sensor, data.valor_patron, data.valor_leido, offset, u['id_usuario']))
    conn.commit(); cur.close(); conn.close()
    return {"status": "ok", "offset": offset}

@app.get("/api/calibracion")
def ver_calibracion(token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    auth(cur, token, ['Servicio Técnico'])
    cur.execute("""SELECT DISTINCT ON (sensor) sensor, valor_patron, valor_leido, offset_lineal, fecha
                   FROM calibracion_sensor ORDER BY sensor, fecha DESC;""")
    data = cur.fetchall()
    cur.close(); conn.close()
    return data

@app.get("/api/sensores/prueba")
def prueba_sensores(token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    auth(cur, token, ['Servicio Técnico'])
    cur.execute("SELECT * FROM lecturas_monitoreo ORDER BY fecha_hora DESC LIMIT 1;")
    raw = cur.fetchone()
    off = get_offsets(cur)
    cur.close(); conn.close()
    return {"cruda": raw, "corregida": corregir(raw, off), "offsets": off}

@app.get("/api/actuadores")
def listar_actuadores(token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    auth(cur, token, ['Servicio Técnico'])
    cur.execute("SELECT id_actuador, nombre_sensor_actuador, estado FROM control_actuadores ORDER BY id_actuador;")
    data = cur.fetchall()
    cur.close(); conn.close()
    return data

@app.post("/api/actuadores/{id_actuador}")
def set_actuador(id_actuador: int, estado: bool, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Servicio Técnico'])
    cur.execute("""UPDATE control_actuadores SET estado = %s, fecha_ultima_modificacion = NOW(), id_tecnico_modifico = %s
                   WHERE id_actuador = %s RETURNING id_actuador;""", (estado, u['id_usuario'], id_actuador))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(status_code=404, detail="Actuador no existe.")
    conn.commit(); cur.close(); conn.close()
    return {"status": "ok", "estado": estado}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)