#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import re
import subprocess
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from threading import Thread

# ==== CONFIGURACIÓN DEL BOT ====
TOKEN = 'TU_TOKEN_AQUI' # Sustituye por tu ID real
bot = telebot.TeleBot(TOKEN)

# Rutas de ficheros
MODO_SEGURO_FILE = "/etc/security/seguro.txt"
BLOQUEADOS_FILE = "/etc/security/bloqueados.txt"
PENDIENTES_FILE = "/etc/security/pendientes.txt"

# ID del administrador en Telegram
ADMIN_ID = TU_TOKEN_AQUI  # Sustituye por tu ID real

# ========== FUNCIONES AUXILIARES ==========

def escribir_log(mensaje):
    """Escribe un log personalizado en /var/log/bot_acceso.log."""
    with open('/var/log/bot_acceso.log', 'a', encoding='utf-8') as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {mensaje}\n")

def expulsar_usuarios_no_root():
    """
    Expulsa a todos los usuarios logueados en SSH excepto root.
    Se usa 'who' para listar los usuarios y 'pkill -u' para matarlos.
    """
    salida = subprocess.getoutput("who | awk '{print $1}'")
    usuarios = set(salida.split())
    for user in usuarios:
        if user != "root":
            subprocess.run(["sudo", "pkill", "-u", user])
    escribir_log("Expulsados todos los usuarios excepto root (modo seguro).")

def bloquear_usuario(usuario, ip):
    """
    Marca a un usuario como bloqueado (añadiendo entrada a bloqueados.txt).
    Opcionalmente, bloquear IP con iptables.
    """
    try:
        with open(BLOQUEADOS_FILE, 'r', encoding='utf-8') as f:
            lineas = f.read().splitlines()
    except FileNotFoundError:
        lineas = []

    existe = any(line.startswith(f"{usuario}:") for line in lineas)
    if not existe:
        lineas.append(f"{usuario}:{ip}")
        with open(BLOQUEADOS_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(lineas) + "\n")

    # (OPCIONAL) Para bloquear la IP con iptables:
    # subprocess.run(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)

    escribir_log(f"🚫 Usuario {usuario} (IP {ip}) bloqueado.")

def desbloquear_usuario(usuario):
    """
    Elimina a un usuario de bloqueados.txt.
    Además podríamos eliminar la regla iptables si se guardase la IP.
    """
    try:
        with open(BLOQUEADOS_FILE, 'r', encoding='utf-8') as f:
            lineas = f.read().splitlines()
    except FileNotFoundError:
        lineas = []

    nuevas = []
    ip_a_desbloquear = None
    for linea in lineas:
        if linea.startswith(f"{usuario}:"):
            _, ip_a_desbloquear = linea.split(":", 1)
        else:
            nuevas.append(linea)

    with open(BLOQUEADOS_FILE, 'w', encoding='utf-8') as f:
        if nuevas:
            f.write("\n".join(nuevas) + "\n")

    # (OPCIONAL) Quitar la regla iptables si se había añadido
    # if ip_a_desbloquear:
    #     subprocess.run(f"sudo iptables -D INPUT -s {ip_a_desbloquear} -j DROP", shell=True)

    escribir_log(f"🟢 Usuario {usuario} desbloqueado.")

def anyadir_pendiente(usuario, ip):
    """
    Añade un usuario:ip a la lista de pendientes (si no estaba ya).
    """
    try:
        with open(PENDIENTES_FILE, 'r', encoding='utf-8') as f:
            lineas = f.read().splitlines()
    except FileNotFoundError:
        lineas = []

    existe = any(line.startswith(f"{usuario}:") for line in lineas)
    if not existe:
        lineas.append(f"{usuario}:{ip}")
        with open(PENDIENTES_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(lineas) + "\n")

def eliminar_de_pendientes(usuario):
    """
    Elimina todas las entradas de 'usuario' en el fichero pendientes.txt
    """
    try:
        with open(PENDIENTES_FILE, 'r', encoding='utf-8') as f:
            lineas = f.read().splitlines()
    except FileNotFoundError:
        lineas = []

    nuevas = [l for l in lineas if not l.startswith(f"{usuario}:")]
    with open(PENDIENTES_FILE, 'w', encoding='utf-8') as f:
        if nuevas:
            f.write("\n".join(nuevas) + "\n")

def activar_modo_seguro():
    """
    Crea el fichero de modo seguro y expulsa a todos los usuarios excepto root.
    """
    with open(MODO_SEGURO_FILE, 'w', encoding='utf-8') as f:
        f.write("1\n")
    expulsar_usuarios_no_root()
    escribir_log("🚨 Modo seguro ACTIVADO.")
    return "🚨 Modo seguro activado. Todos los usuarios (excepto root) han sido desconectados."

def desactivar_modo_seguro():
    """
    Elimina el fichero de modo seguro y permite conexiones.
    """
    if os.path.exists(MODO_SEGURO_FILE):
        os.remove(MODO_SEGURO_FILE)
    escribir_log("🟢 Modo seguro DESACTIVADO.")
    return "🟢 Modo seguro desactivado. Ahora se permiten conexiones."

def top_10_procesos():
    """
    Lista los 10 procesos que más memoria consumen.
    """
    procesos = subprocess.getoutput("ps aux --sort=-%mem | head -n 11")
    mensaje = "🔍 *Top 10 procesos por uso de memoria:*\n```\n" + procesos + "\n```"
    return mensaje

def info_recursos():
    """
    Muestra el uso de RAM y disco en el servidor.
    """
    # === RAM ===
    free_out = subprocess.getoutput("free -m")
    lines = free_out.splitlines()
    mem_info = lines[1].split()
    total_mem_mb = float(mem_info[1])
    used_mem_mb = float(mem_info[2])
    total_gb = total_mem_mb / 1024.0
    used_gb = used_mem_mb / 1024.0
    percent_mem = (used_gb / total_gb) * 100 if total_gb > 0 else 0

    # === DISCO ===
    disk_out = subprocess.getoutput("df -h / | tail -1")
    disk_cols = disk_out.split()
    disk_size = disk_cols[1]
    disk_used = disk_cols[2]
    disk_use_pct = disk_cols[4]

    msg = (
        f"🖥 *Recursos del servidor:*\n\n"
        f"• RAM usada: {used_gb:.2f} GB / {total_gb:.2f} GB  ({percent_mem:.1f}%)\n"
        f"• Disco en /: {disk_used} / {disk_size}  ({disk_use_pct})\n"
    )
    return msg

# ========== MONITORIZACIÓN DE /var/log/auth.log ==========

def monitorear_intentos_acceso():
    """
    Lee /var/log/auth.log buscando accesos SSH aceptados y notifica para aprobar/denegar.
    """
    with open('/var/log/auth.log', 'r') as log:
        log.seek(0, 2)  # Ir al final del archivo

        patron = re.compile(
            r"sshd.*Accepted (?:password|publickey|keyboard-interactive) for (\w+) from (\d+\.\d+\.\d+\.\d+)"
        )

        while True:
            linea = log.readline()
            if not linea:
                time.sleep(1)
                continue

            match = patron.search(linea)
            if match:
                usuario = match.group(1)
                ip = match.group(2)

                # root no se bloquea
                if usuario == "root":
                    escribir_log(f"Login root detectado desde {ip}, sin restricciones.")
                    continue

                # Si está activado el modo seguro, bloqueo automático
                if os.path.exists(MODO_SEGURO_FILE):
                    escribir_log(f"⛔ Conexión bloqueada (modo seguro): {usuario} @ {ip}")
                    bot.send_message(
                        ADMIN_ID,
                        f"⛔ Se detectó intento de {usuario} desde {ip}, pero el servidor está en *modo seguro*."
                    )
                    continue

                # Añadir a pendientes y notificar al admin
                anyadir_pendiente(usuario, ip)

                markup = InlineKeyboardMarkup()
                markup.add(
                    InlineKeyboardButton("✅ Aceptar", callback_data=f"aceptar_{usuario}_{ip}"),
                    InlineKeyboardButton("❌ Rechazar", callback_data=f"rechazar_{usuario}_{ip}")
                )

                bot.send_message(
                    ADMIN_ID,
                    f"⚠️ *Nueva solicitud de acceso:*\n"
                    f"👤 Usuario: `{usuario}`\n"
                    f"🌍 IP: `{ip}`\n\n"
                    f"¿Deseas *aceptar* o *rechazar*?",
                    parse_mode="Markdown",
                    reply_markup=markup
                )

# ========== MANEJO DE RESPUESTAS (CALLBACK) ==========

@bot.callback_query_handler(func=lambda call: call.data.startswith(("aceptar_", "rechazar_")))
def callback_handler(call):
    """
    Maneja los botones "Aceptar" o "Rechazar" enviados al admin.
    """
    accion, usuario, ip = call.data.split("_", 2)

    if accion == "aceptar":
        eliminar_de_pendientes(usuario)
        bot.send_message(
            ADMIN_ID,
            f"✅ Conexión aprobada para *{usuario}* desde `{ip}`.\n"
            f"El usuario podrá acceder (debe reintentar).",
            parse_mode="Markdown"
        )
        escribir_log(f"Conexión aprobada para {usuario}@{ip}.")

    elif accion == "rechazar":
        eliminar_de_pendientes(usuario)
        bloquear_usuario(usuario, ip)
        bot.send_message(
            ADMIN_ID,
            f"🚨 Conexión rechazada para *{usuario}* desde `{ip}`.\n"
            "El usuario ha sido bloqueado.",
            parse_mode="Markdown"
        )
        escribir_log(f"Conexión rechazada y usuario bloqueado: {usuario}@{ip}")

    bot.answer_callback_query(call.id, text="Hecho")

# ========== COMANDOS DE TELEGRAM ==========

#
# NUEVOS COMANDOS:
#

@bot.message_handler(commands=['start'])
def cmd_start(message):
    """
    Mensaje de bienvenida cuando el usuario inicia el bot.
    """
    bot.send_message(
        message.chat.id,
        "🤖¡Bienvenido/a al bot de administración!\n"
        "Si necesitas ayuda, escribe /help para ver todos los comandos disponibles."
    )

@bot.message_handler(commands=['help'])
def cmd_help(message):
    """
    Muestra todos los comandos disponibles.
    """
    help_text = (
        "🤖 Comandos disponibles:\n"
        "/start - Muestra este mensaje de bienvenida\n"
        "/help - Muestra esta lista de comandos\n"
        "/modo_seguro - Activa el modo seguro\n"
        "/desactivar_seguro - Desactiva el modo seguro\n"
        "/listar_bloqueados - Muestra usuarios bloqueados\n"
        "/listar_no_bloqueados - Muestra usuarios no bloqueados\n"
        "/top_procesos - Muestra el top 10 de procesos\n"
        "/recursos - Muestra información de recursos\n"
        "/usuarios - Lista usuarios conectados\n"
    )
    bot.send_message(message.chat.id, help_text)

@bot.message_handler(commands=['usuarios'])
def cmd_usuarios(message):
    """
    Muestra los usuarios actualmente conectados al servidor (solo admin).
    """
    if message.chat.id == ADMIN_ID:
        connected_users = subprocess.getoutput("who | awk '{print $1}'")
        if connected_users.strip():
            unique_users = set(connected_users.split())
            text = "👥 Usuarios actualmente conectados:\n"
            for user in unique_users:
                text += f"• {user}\n"
        else:
            text = "👥 No hay usuarios conectados en este momento."
        bot.send_message(ADMIN_ID, text)


@bot.message_handler(commands=['modo_seguro'])
def cmd_modo_seguro(message):
    if message.chat.id == ADMIN_ID:
        resp = activar_modo_seguro()
        bot.send_message(ADMIN_ID, resp)

@bot.message_handler(commands=['desactivar_seguro'])
def cmd_desactivar_seguro(message):
    if message.chat.id == ADMIN_ID:
        resp = desactivar_modo_seguro()
        bot.send_message(ADMIN_ID, resp)

@bot.message_handler(commands=['listar_bloqueados'])
def cmd_listar_bloqueados(message):
    if message.chat.id != ADMIN_ID:
        return

    if not os.path.exists(BLOQUEADOS_FILE):
        bot.send_message(ADMIN_ID, "No hay usuarios bloqueados.")
        return

    with open(BLOQUEADOS_FILE, 'r', encoding='utf-8') as f:
        lineas = f.read().strip().splitlines()

    if not lineas:
        bot.send_message(ADMIN_ID, "No hay usuarios bloqueados.")
        return

    texto = "🚫 *Usuarios bloqueados:*\n"
    for l in lineas:
        texto += f"• `{l}`\n"
    bot.send_message(ADMIN_ID, texto, parse_mode="Markdown")

@bot.message_handler(commands=['listar_no_bloqueados'])
def cmd_listar_no_bloqueados(message):
    if message.chat.id != ADMIN_ID:
        return

    bloqueados = set()
    if os.path.exists(BLOQUEADOS_FILE):
        with open(BLOQUEADOS_FILE, 'r', encoding='utf-8') as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    user_block = linea.split(":")[0]
                    bloqueados.add(user_block)

    pendientes = set()
    if os.path.exists(PENDIENTES_FILE):
        with open(PENDIENTES_FILE, 'r', encoding='utf-8') as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    user_pend = linea.split(":")[0]
                    pendientes.add(user_pend)

    salida_passwd = subprocess.getoutput("awk -F: '$3 >= 1000 {print $1}' /etc/passwd")
    usuarios_sistema = salida_passwd.split()

    no_bloqueados = []
    for u in usuarios_sistema:
        if u == "root":
            continue
        if u not in bloqueados and u not in pendientes:
            no_bloqueados.append(u)

    if not no_bloqueados:
        bot.send_message(ADMIN_ID, "No hay usuarios libres (o todos están bloqueados/pendientes).")
        return

    texto = "🟢 *Usuarios no bloqueados (ni pendientes):*\n"
    for nb in no_bloqueados:
        texto += f"• `{nb}`\n"
    bot.send_message(ADMIN_ID, texto, parse_mode="Markdown")

@bot.message_handler(commands=['top_procesos'])
def cmd_top_procesos(message):
    if message.chat.id == ADMIN_ID:
        bot.send_message(ADMIN_ID, top_10_procesos(), parse_mode="Markdown")

@bot.message_handler(commands=['recursos'])
def cmd_recursos(message):
    if message.chat.id == ADMIN_ID:
        bot.send_message(ADMIN_ID, info_recursos(), parse_mode="Markdown")

# ========== MAIN ==========

if __name__ == '__main__':
    # Lanzamos hilo para monitorizar /var/log/auth.log
    t = Thread(target=monitorear_intentos_acceso, daemon=True)
    t.start()

    # Iniciamos el bot
    bot.polling()
