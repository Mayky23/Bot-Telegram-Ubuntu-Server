# 🚀 Bot de Telegram para Monitorización y Seguridad en Ubuntu Server

Este proyecto implementa un bot de Telegram diseñado para monitorear, gestionar y reforzar la seguridad de un servidor Ubuntu. Proporciona herramientas avanzadas de supervisión y control en tiempo real a través de comandos de Telegram.

## 🛠 Funcionalidades principales

✅ **Monitoreo del Servidor**  
- Consulta en tiempo real del uso de **CPU, RAM y disco**.  
- Listado de **usuarios conectados** y detalles relevantes.  
- Identificación de los **procesos que más recursos consumen**.  

✅ **Gestión de Accesos**  
- **Bloquear/desbloquear usuarios** directamente desde Telegram.  
- **Modo seguro**: bloquea todas las conexiones entrantes en caso de amenaza.  

✅ **Ciberseguridad**  
- Notificaciones sobre intentos de acceso de usuarios bloqueados.  
- Control dinámico del estado del servidor (bloqueado/operativo).  
- Integración con **PAM** para gestionar accesos SSH.  

✅ **Automatización**  
- Comandos simples de Telegram para administrar el servidor desde cualquier parte del mundo.  

## 📌 Requisitos previos

- Un servidor Ubuntu con acceso a terminal.  
- Telegram instalado en el dispositivo del administrador.  

## 📜 Comandos disponibles

| Comando              | Descripción |
|----------------------|------------|
| `/start`            | Muestra mensaje de bienvenida |
| `/help`             | Lista los comandos disponibles |
| `/modo_seguro`      | Activa el modo seguro (bloqueo total) |
| `/desactivar_seguro`| Desactiva el modo seguro |
| `/listar_bloqueados` | Muestra usuarios bloqueados |
| `/listar_no_bloqueados` | Muestra usuarios no bloqueados |
| `/top_procesos`     | Muestra los procesos que más consumen recursos |
| `/recursos`        | Muestra información sobre CPU, RAM y disco |
| `/usuarios`        | Lista usuarios conectados |