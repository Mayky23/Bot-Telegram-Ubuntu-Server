#!/bin/bash

# Archivo con la lista de usuarios bloqueados
BLOQUEADOS_FILE="/etc/security/bloqueados.txt"

# Archivo que indica si el servidor está en modo seguro
MODO_SEGURO_FILE="/etc/security/seguro.txt"

# Archivo donde se almacenan usuarios en espera de aprobación
PENDIENTES_FILE="/etc/security/pendientes.txt"

# Obtener el nombre del usuario que intenta conectarse
USER_NAME="$PAM_USER"

# Si existe el archivo de modo seguro y NO es root, bloquear
if [ -f "$MODO_SEGURO_FILE" ] && [ "$USER_NAME" != "root" ]; then
    echo "********************************"
    echo "** EL SERVIDOR ESTÁ BLOQUEADO **"
    echo "********************************"
    echo "Por motivos de seguridad, el servidor está actualmente bloqueado."
    echo "Contacte con el equipo de sistemas."
    exit 1
fi

# Verificar si el usuario está bloqueado
# Asumimos que en bloqueados.txt cada línea tiene el formato usuario:IP
# Pero como queremos bloquear al usuario en cualquier IP, basta con buscar "usuario:"
if grep -q "^${USER_NAME}:" "$BLOQUEADOS_FILE" 2>/dev/null; then
    echo "****************************************************************"
    echo "**  EL ADMINISTRADOR DEL SERVICIO HA BLOQUEADO ESTA CONEXIÓN  **"
    echo "****************************************************************"
    echo "Contacte con el departamento de sistemas para más información."
    exit 1
fi

# Verificar si el usuario está en la lista de espera de aprobación
# Igual que bloqueados, pendientes.txt tiene líneas tipo usuario:IP
if grep -q "^${USER_NAME}:" "$PENDIENTES_FILE" 2>/dev/null; then
    echo "**************************************************************"
    echo "**  EL ADMINISTRADOR DEBE ACEPTAR ESTA CONEXIÓN.            **"
    echo "**  MANTÉNGASE A LA ESPERA...                               **"
    echo "**************************************************************"
    exit 1
fi

# Si no hay restricciones, permitir el acceso
exit 0