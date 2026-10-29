#app.py
import os
import secrets
import hashlib
from typing import Optional
import time
from fastapi import FastAPI, HTTPException, Query, Header
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
    try:
        cur.execute("SELECT DISTINCT ON (sensor) sensor, offset_lineal FROM calibracion_sensor ORDER BY sensor, fecha DESC;")
        return {r['sensor']: float(r['offset_lineal']) for r in cur.fetchall()}
    except Exception:
        cur.connection.rollback()
        return {}

def corregir(lectura, offsets):
    if not lectura:
        return None
    l = dict(lectura)
    for s, col in COLS.items():
        if l.get(col) is not None:
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
    q, params = "SELECT * FROM paciente WHERE TRIM(carnet_identidad) = %s", [ci.strip()]
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
    midiendo = ESTADO_ESP32["pedir_presion"] or ESTADO_ESP32["estado_presion"] == 1
    for a in data:
        if a['nombre_sensor_actuador'] == 'Bomba de aire':
            a['estado'] = bool(midiendo)
            a['solo_lectura'] = True
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

ESP32_KEY = os.getenv("ESP32_KEY")
ESTADO_ESP32 = {"ultimo_contacto": 0.0, "pedir_presion": False, "estado_presion": 0}  # 0 reposo,1 midiendo,2 ok,3 error
SESION_ACTIVA = {}

def esp32_conectado():
    return (time.time() - ESTADO_ESP32["ultimo_contacto"]) < 25
def marcar_bomba(encendida: bool):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("""UPDATE control_actuadores SET estado = %s, fecha_ultima_modificacion = NOW()
                       WHERE nombre_sensor_actuador = 'Bomba de aire';""", (encendida,))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        print(f"ERROR actualizando bomba: {e}")
# ---------- SESIONES DE MONITOREO ----------
def paciente_permitido(cur, u, id_paciente):
    q = "SELECT id_paciente, nombre, primer_apellido, segundo_apellido, carnet_identidad FROM paciente WHERE id_paciente = %s"
    params = [id_paciente]
    if u['rol'] == 'Operador':
        q += " AND id_operador_asignado = %s"; params.append(u['id_usuario'])
    cur.execute(q, params)
    p = cur.fetchone()
    if not p:
        raise HTTPException(status_code=404, detail="Paciente no encontrada.")
    return p

def sesion_permitida(cur, u, id_sesion):
    q = """SELECT s.* FROM sesion_monitoreo s JOIN paciente p ON p.id_paciente = s.id_paciente
           WHERE s.id_sesion = %s"""
    params = [id_sesion]
    if u['rol'] == 'Operador':
        q += " AND p.id_operador_asignado = %s"; params.append(u['id_usuario'])
    cur.execute(q, params)
    s = cur.fetchone()
    if not s:
        raise HTTPException(status_code=404, detail="Sesión no encontrada.")
    return s

@app.post("/api/sesion/iniciar")
def iniciar_sesion(id_paciente: int, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Operador'])
    paciente_permitido(cur, u, id_paciente)
    cur.execute("UPDATE sesion_monitoreo SET fecha_fin = NOW() WHERE id_paciente = %s AND fecha_fin IS NULL;", (id_paciente,))
    cur.execute("INSERT INTO sesion_monitoreo (id_paciente, id_operador) VALUES (%s,%s) RETURNING id_sesion;",
                (id_paciente, u['id_usuario']))
    s = cur.fetchone()
    cur.execute("UPDATE paciente SET fecha_ultima_visita = NOW() WHERE id_paciente = %s;", (id_paciente,))
    conn.commit(); cur.close(); conn.close()
    SESION_ACTIVA.clear()
    SESION_ACTIVA.update(id_sesion=s['id_sesion'], id_paciente=id_paciente)
    ESTADO_ESP32.update(pedir_presion=False, estado_presion=0)
    return {"status": "ok", "id_sesion": s['id_sesion']}

@app.post("/api/sesion/{id_sesion}/finalizar")
def finalizar_sesion(id_sesion: int, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Operador'])
    sesion_permitida(cur, u, id_sesion)
    cur.execute("UPDATE sesion_monitoreo SET fecha_fin = NOW() WHERE id_sesion = %s AND fecha_fin IS NULL;", (id_sesion,))
    conn.commit(); cur.close(); conn.close()
    if SESION_ACTIVA.get("id_sesion") == id_sesion:
        SESION_ACTIVA.clear()
        ESTADO_ESP32["pedir_presion"] = False
    return {"status": "ok"}

@app.get("/api/sesion/{id_sesion}/en-vivo")
def sesion_en_vivo(id_sesion: int, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Operador'])
    sesion_permitida(cur, u, id_sesion)
    cur.execute("""
        SELECT l.id_lectura, l.fecha_hora, l.frecuencia_cardiaca_materna, l.frecuencia_cardiaca_fetal,
               COALESCE(l.presion_sistolica, p.presion_sistolica)   AS presion_sistolica,
               COALESCE(l.presion_diastolica, p.presion_diastolica) AS presion_diastolica
        FROM lecturas_monitoreo l
        LEFT JOIN LATERAL (
            SELECT presion_sistolica, presion_diastolica FROM lecturas_monitoreo
            WHERE id_sesion = l.id_sesion AND presion_sistolica IS NOT NULL AND fecha_hora <= l.fecha_hora
            ORDER BY fecha_hora DESC LIMIT 1
        ) p ON TRUE
        WHERE l.id_sesion = %s
        ORDER BY l.fecha_hora DESC LIMIT 20;""", (id_sesion,))
    lect = cur.fetchall()
    cur.execute("""SELECT * FROM lecturas_monitoreo WHERE id_sesion = %s AND presion_sistolica IS NOT NULL
                   ORDER BY fecha_hora DESC LIMIT 1;""", (id_sesion,))
    pres = cur.fetchone()
    off = get_offsets(cur)
    cur.close(); conn.close()
    lect = [corregir(l, off) for l in lect]

    vivo = ESTADO_ESP32.get("ultima")
    ultima = None
    if vivo and vivo["id_sesion"] == id_sesion and time.time() - vivo["t"] < 15:
        ultima = corregir({"frecuencia_cardiaca_materna": vivo["fc_m"],
                           "frecuencia_cardiaca_fetal": vivo["fc_f"],
                           "presion_sistolica": None, "presion_diastolica": None}, off)
    return {"ultima": ultima, "ultima_presion": corregir(pres, off), "recientes": lect,
            "esp32_conectado": esp32_conectado(),
            "estado_presion": ESTADO_ESP32["estado_presion"],
            "pedida": ESTADO_ESP32["pedir_presion"]}

@app.get("/api/paciente/{id_paciente}/sesiones")
def listar_sesiones(id_paciente: int, desde: Optional[str] = None, hasta: Optional[str] = None,
                    token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Administrador', 'Operador'])
    paciente_permitido(cur, u, id_paciente)
    q = """SELECT s.id_sesion, s.fecha_inicio, s.fecha_fin, COUNT(l.id_lectura) AS n_lecturas,
                  AVG(l.frecuencia_cardiaca_materna) AS fc_materna, AVG(l.frecuencia_cardiaca_fetal) AS fc_fetal,
                  AVG(l.presion_sistolica) AS presion_sistolica, AVG(l.presion_diastolica) AS presion_diastolica
           FROM sesion_monitoreo s LEFT JOIN lecturas_monitoreo l ON l.id_sesion = s.id_sesion
           WHERE s.id_paciente = %s"""
    params = [id_paciente]
    if desde:
        q += " AND s.fecha_inicio >= %s"; params.append(desde)
    if hasta:
        q += " AND s.fecha_inicio < (%s::date + 1)"; params.append(hasta)
    q += " GROUP BY s.id_sesion ORDER BY s.fecha_inicio DESC;"
    cur.execute(q, params)
    rows = cur.fetchall()
    off = get_offsets(cur)
    cur.close(); conn.close()
    for r in rows:   # promedios con la calibración aplicada
        for k in COLS:
            r[k] = round(float(r[k]) + off.get(k, 0), 1) if r[k] is not None else None
    return rows

@app.get("/api/sesion/{id_sesion}/lecturas")
def lecturas_sesion(id_sesion: int, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Administrador', 'Operador'])
    sesion_permitida(cur, u, id_sesion)
    cur.execute("SELECT * FROM lecturas_monitoreo WHERE id_sesion = %s ORDER BY fecha_hora;", (id_sesion,))
    lect = cur.fetchall()
    off = get_offsets(cur)
    cur.close(); conn.close()
    return [corregir(l, off) for l in lect]

class DatosESP32(BaseModel):
    frecuencia_cardiaca_materna: Optional[float] = None
    frecuencia_cardiaca_fetal: Optional[float] = None
    presion_sistolica: Optional[float] = None
    presion_diastolica: Optional[float] = None
    estado_presion: int = 0

@app.post("/api/sesion/{id_sesion}/presion/iniciar")
def iniciar_toma_presion(id_sesion: int, token: str = Query(...)):
    conn = get_db_connection(); cur = conn.cursor()
    u = auth(cur, token, ['Operador'])
    s = sesion_permitida(cur, u, id_sesion)
    cur.close(); conn.close()
    if s['fecha_fin'] is not None or SESION_ACTIVA.get("id_sesion") != id_sesion:
        raise HTTPException(status_code=400, detail="La sesión no está activa.")
    if not esp32_conectado():
        raise HTTPException(status_code=503, detail="El ESP32 no está conectado.")
    if ESTADO_ESP32["pedir_presion"] or ESTADO_ESP32["estado_presion"] == 1:
        raise HTTPException(status_code=409, detail="Ya hay una toma de presión en curso.")
    ESTADO_ESP32.update(pedir_presion=True, estado_presion=0)
    marcar_bomba(True)
    return {"status": "ok"}

@app.post("/api/esp32/datos")
def recibir_datos_esp32(data: DatosESP32, x_api_key: Optional[str] = Header(None)):
    if not ESP32_KEY or not x_api_key or not secrets.compare_digest(x_api_key, ESP32_KEY):
        raise HTTPException(status_code=401, detail="Dispositivo no autorizado.")
    ESTADO_ESP32["ultimo_contacto"] = time.time()

    ep = data.estado_presion
    if ep in (1, 2, 3):
        ESTADO_ESP32["pedir_presion"] = False
        ESTADO_ESP32["estado_presion"] = ep
        if ep in (2, 3):
            marcar_bomba(False)
    elif ESTADO_ESP32["estado_presion"] == 1:
        ESTADO_ESP32["estado_presion"] = 0      # el ESP32 perdió la medición (reinicio)
        marcar_bomba(False)

    if not SESION_ACTIVA:
        if ESTADO_ESP32["pedir_presion"]:
            ESTADO_ESP32["pedir_presion"] = False
            marcar_bomba(False)
        return {"status": "ok", "sesion_activa": False, "medir_presion": False}

    def norm(x):   # 0 o null = sin señal
        return None if (x is None or x <= 0) else round(x)
    fcm, fcf = norm(data.frecuencia_cardiaca_materna), norm(data.frecuencia_cardiaca_fetal)
    ESTADO_ESP32["ultima"] = {"id_sesion": SESION_ACTIVA["id_sesion"], "fc_m": fcm, "fc_f": fcf, "t": time.time()}
    sis = norm(data.presion_sistolica) if ep == 2 else None
    dia = norm(data.presion_diastolica) if ep == 2 else None
    valores = (fcm, fcf, sis, dia)

    guardado = True
    if any(x is not None for x in valores):      # si los 4 son 0, no se guarda nada
        conn = cur = None
        try:
            conn = get_db_connection(); cur = conn.cursor()
            cur.execute("""INSERT INTO lecturas_monitoreo
                (id_sesion, id_paciente, frecuencia_cardiaca_materna, frecuencia_cardiaca_fetal,
                 presion_sistolica, presion_diastolica) VALUES (%s,%s,%s,%s,%s,%s);""",
                (SESION_ACTIVA["id_sesion"], SESION_ACTIVA["id_paciente"], *valores))
            conn.commit()
        except Exception as e:
            guardado = False
            print(f"ERROR guardando lectura del ESP32: {e}")
            if conn: conn.rollback()
        finally:
            if cur: cur.close()
            if conn: conn.close()

    return {"status": "ok", "sesion_activa": True, "guardado": guardado,
            "medir_presion": ESTADO_ESP32["pedir_presion"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)