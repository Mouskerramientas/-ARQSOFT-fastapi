# Trabajo de `FastAPI`

**Clase**: Arquitectura de Software

## Integrantes del grupo:

- Karol Guerrero
- Fabián Rincón
- Nicolás Rodríguez
- Daniel Velasco

## Pasos:

1. Crear entorno virtual con python

```sh
python3 -m venv .venv
```

2. Activar el entorno virtual. En linux:

```sh
source .venv/bin/activate
```

3. Instalar las dependencias necesarias:

```sh
pip install -r requirements.txt
```

## Contenido:

1. `app.py` -> Autenticación básica con FastAPI

   - Ejecutar con:

   ```sh
   fastapi dev app.py
   ```

2. `failures.py` -> Monolito del proyecto de fallas en servidores. Solo contiene autenticación y el servicio de almacenamiento.
   - Ejecutar con:
   ```sh
   fastapi dev failures.py
   ```
