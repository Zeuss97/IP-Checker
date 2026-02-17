# Registro de IPs con monitoreo de ping

Aplicación web simple para:

- Registrar direcciones IP (con alias opcional).
- Ejecutar ping automáticamente cada 12 horas a todas las IPs registradas.
- Guardar resultado del ping y la fecha/hora del último intento.
- Resolver hostname (equivalente práctico a `ping -a`) para identificar el nombre del equipo cuando sea posible.
- Filtrar IPs por segmento /24 (por ejemplo `192.168.56.0/24` o formato corto `56/24`).
- Editar cada host con detalles: nombre, tipo de equipo, ubicación, alias y notas adicionales.

## Requisitos

- Python 3.10+
- Dependencias de `requirements.txt`

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

La app queda disponible en `http://localhost:5000`.

## Notas

- En Windows se usa `ping -a` directamente.
- En Linux/macOS se usa `ping -c 1` y resolución DNS inversa (`socket.gethostbyaddr`) para obtener el hostname.
- El intervalo está configurado en 12 horas (`PING_INTERVAL_SECONDS`).
- También puedes lanzar el ping manualmente desde el botón **Ejecutar ping ahora**.

- El filtro por segmento permite separar fácilmente rangos como 56/24 y 59/24.

- Cada IP tiene un botón **Editar host** para modificar sus datos en cualquier momento.
