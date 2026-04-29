# Tarea 11 — B5: Git client para acceso remoto al código fuente

**Archivo a crear:** `zeronoise/clients/git_client.py`
**Tiempo estimado:** 20 minutos
**Dependencias:** Ninguna
**Cuándo usar:** Solo cuando ZeroNoise se despliegue en servidor centralizado.
En modo local y pipeline CI/CD, `project_path` es siempre local — esto no se necesita.

---

## Problema

En un servidor centralizado, el código fuente no está en el filesystem local.
ZeroNoise necesita clonar el repo temporalmente para Stage 2/3, y borrarlo al terminar.

## 1. Agregar en `.env.example`

```env
# Git — solo requerido si ZeroNoise corre en servidor remoto
GIT_BASE_URL=https://gitlab.tuempresa.com
GIT_TOKEN=    # Token con scope read_repository (read-only)
```

## 2. Agregar en `config.py`

```python
git_base_url: str = ""
git_token: str = ""
```

## 3. Crear `zeronoise/clients/git_client.py`

```python
"""
git_client.py — Acceso temporal al código fuente vía Git.

Permite que ZeroNoise clone el repositorio en un directorio temporal,
corra el análisis, y borre el directorio al terminar.

SEGURIDAD:
  - El código fuente se almacena SOLO durante el análisis (context manager)
  - Se borra inmediatamente en el finally — incluso si hay error
  - El token tiene scope read-only
  - Nunca se loggea la URL con el token embebido

Requiere: git instalado en el servidor de ZeroNoise
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional


class GitClient:

    def __init__(self, git_token: str, git_base_url: str):
        self.git_token = git_token
        self.git_base_url = git_base_url.rstrip("/")

    @asynccontextmanager
    async def checkout(self, repo_path: str, commit_sha: str = "HEAD"):
        """
        Context manager: clona el repo, yield la ruta local, borra al salir.

        Args:
            repo_path:   Ruta relativa del repo en GitLab/GitHub.
                         Ej: "backend/microservicio-clientes"
            commit_sha:  Commit a analizar. "HEAD" para el último.

        Uso:
            async with git_client.checkout("grupo/repo", "abc123") as local_path:
                result = await analyze_package_reachability(purl, local_path)
            # local_path ya fue borrado aquí
        """
        tmp_dir = tempfile.mkdtemp(prefix="zeronoise_")
        try:
            repo_url = self._build_auth_url(repo_path)
            await self._git(["clone", "--depth=1", repo_url, tmp_dir])
            if commit_sha and commit_sha != "HEAD":
                await self._git(["fetch", "--depth=1", "origin", commit_sha], cwd=tmp_dir)
                await self._git(["checkout", commit_sha], cwd=tmp_dir)
            yield tmp_dir
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _build_auth_url(self, repo_path: str) -> str:
        """URL con token embebido. Nunca loggear esta URL."""
        base = self.git_base_url
        # https://oauth2:TOKEN@gitlab.empresa.com/grupo/repo.git
        auth_base = base.replace("https://", f"https://oauth2:{self.git_token}@")
        return f"{auth_base}/{repo_path}.git"

    async def _git(self, args: list[str], cwd: Optional[str] = None) -> None:
        proc = await asyncio.create_subprocess_exec(
            "git", *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"git {args[0]} tardó más de 120s")

        if proc.returncode != 0:
            # No incluir la URL en el error (puede contener el token)
            safe_args = [a for a in args if "://" not in a]
            raise RuntimeError(
                f"git {safe_args[0]} falló (código {proc.returncode}): "
                f"{stderr.decode('utf-8', errors='ignore')[:200]}"
            )


def get_git_client() -> Optional[GitClient]:
    """
    Factory que retorna un GitClient si está configurado, None si no.
    Permite que el código llamador haga: if client := get_git_client(): ...
    """
    from zeronoise.config import get_settings
    settings = get_settings()
    if not settings.git_token or not settings.git_base_url:
        return None
    return GitClient(
        git_token=settings.git_token,
        git_base_url=settings.git_base_url,
    )
```

## 4. Cómo se integra en `tools/dt_background.py` (cuando se necesite)

Modificar `analyze_project_vulnerabilities` para aceptar `repo_path` opcional:

```python
async def analyze_project_vulnerabilities(
    project_uuid: str,
    project_path: str = "",        # ruta local (modo local/CI)
    repo_path: str = "",           # ruta en GitLab (modo servidor remoto)
    commit_sha: str = "HEAD",
    ...
) -> dict:

    # Resolver project_path según el modo
    if not project_path and repo_path:
        from zeronoise.clients.git_client import get_git_client
        client = get_git_client()
        if not client:
            return {"error": "validation_error",
                    "message": "repo_path requiere GIT_TOKEN y GIT_BASE_URL en .env"}
        async with client.checkout(repo_path, commit_sha) as local_path:
            return await _run_analysis(project_uuid, local_path, ...)
    else:
        return await _run_analysis(project_uuid, project_path, ...)
```

## Verificar

```bash
# Test de conectividad Git (requiere GIT_TOKEN y GIT_BASE_URL en .env)
python -c "
import asyncio
from zeronoise.clients.git_client import get_git_client

async def test():
    client = get_git_client()
    if not client:
        print('GIT_TOKEN o GIT_BASE_URL no configurados')
        return
    async with client.checkout('grupo/microservicio-clientes') as path:
        print(f'Repo clonado en: {path}')
        import os
        print(f'Archivos: {len(list(os.walk(path)))} directorios')
    print('Directorio borrado correctamente')

asyncio.run(test())
"
```

## Lo que NO tocar

Tools MCP existentes — no modificar sus firmas.
`project_path` sigue siendo el parámetro principal — `repo_path` es opcional.
