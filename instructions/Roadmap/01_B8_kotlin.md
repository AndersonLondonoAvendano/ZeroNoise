# Tarea 01 — B8: Soporte Kotlin

**Archivo a modificar:** `zeronoise/analyzers/java_import_scanner.py`
**Tiempo estimado:** 5 minutos
**Dependencias:** Ninguna

---

## Problema

Spring Boot 3.x usa Kotlin. El scanner Java ignora `.kt` — un proyecto Kotlin
que importa una librería vulnerable no se detecta como REACHABLE.

## Cambio

Buscar en `java_import_scanner.py` la constante `_SOURCE_EXTENSIONS` y agregar `.kt`:

```python
# Antes:
_SOURCE_EXTENSIONS = frozenset({".java"})

# Después:
_SOURCE_EXTENSIONS = frozenset({".java", ".kt"})
```

Los patrones de import son idénticos en Kotlin:
```kotlin
import org.springframework.web.bind.annotation.RestController
import io.netty.channel.EventLoopGroup
```

No requiere nuevo scanner — el regex existente funciona sin cambios.

## Verificar

```bash
# Crear un archivo .kt de prueba con un import y confirmar que es detectado
uv run python scripts/poc_stage2.py \
    --project-path <ruta-proyecto-kotlin> \
    --package "pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final"
```

## Lo que NO tocar

Ningún otro archivo.
