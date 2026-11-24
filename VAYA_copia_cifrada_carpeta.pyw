#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copia cifrada de la carpeta donde está este programa.

- Lee únicamente archivos dentro de ROOT (la carpeta del propio script) y sus
  subcarpetas.
- Crea UN archivo de copia cifrada fuera de ROOT.
- Nunca cifra, renombra, elimina ni modifica los archivos originales.
- La restauración se realiza en una carpeta nueva y nunca sobrescribe archivos.

Requisito: pip install cryptography
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ImportError:
    raise SystemExit("Falta cryptography. Instalalo con: python -m pip install cryptography")

ROOT = Path(__file__).resolve().parent
MAGIC = b"VAYA-BACKUP-1\n"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KDF_ITERATIONS = 600_000
CHUNK_SIZE = 1024 * 1024


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, KDF_ITERATIONS, dklen=32
    )


def iter_source_files():
    """Enumera archivos normales bajo ROOT, sin seguir enlaces simbólicos."""
    root_resolved = ROOT.resolve()
    for current, dirs, files in os.walk(root_resolved, followlinks=False):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if not (current_path / d).is_symlink()]
        for filename in files:
            path = current_path / filename
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve()
                if os.path.commonpath((str(root_resolved), str(resolved))) != str(root_resolved):
                    continue
            except (OSError, ValueError):
                continue
            yield path


def build_zip(zip_path: Path) -> int:
    count = 0
    root_resolved = ROOT.resolve()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in iter_source_files():
            relative = path.relative_to(root_resolved).as_posix()
            # El archivo del programa también queda incluido en la copia.
            archive.write(path, arcname=relative)
            count += 1
    return count


def encrypt_zip(zip_path: Path, output_path: Path, password: str) -> None:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce
    key = derive_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    # Escritura temporal y reemplazo final: no deja un archivo final a medio crear.
    temp_output = output_path.with_name(output_path.name + ".part")
    try:
        with zip_path.open("rb") as source, temp_output.open("wb") as target:
            target.write(header)
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                encrypted = encryptor.update(block)
                if encrypted:
                    target.write(encrypted)
            final_block = encryptor.finalize()
            if final_block:
                target.write(final_block)
            target.write(encryptor.tag)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_output, output_path)
    finally:
        try:
            temp_output.unlink(missing_ok=True)
        except OSError:
            pass


def decrypt_to_zip(encrypted_path: Path, zip_path: Path, password: str) -> None:
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    file_size = encrypted_path.stat().st_size
    if file_size < header_len + TAG_LEN:
        raise ValueError("El archivo no tiene un formato VAYA válido o está incompleto.")

    with encrypted_path.open("rb") as source:
        magic = source.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("El archivo seleccionado no es una copia VAYA compatible.")
        salt = source.read(SALT_LEN)
        nonce = source.read(NONCE_LEN)
        header = magic + salt + nonce
        ciphertext_size = file_size - header_len - TAG_LEN
        tag_position = header_len + ciphertext_size
        key = derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(header)

        with zip_path.open("wb") as target:
            remaining = ciphertext_size
            while remaining:
                block = source.read(min(CHUNK_SIZE, remaining))
                if not block:
                    raise ValueError("La copia cifrada está truncada.")
                remaining -= len(block)
                plain = decryptor.update(block)
                if plain:
                    target.write(plain)
            source.seek(tag_position)
            tag = source.read(TAG_LEN)
            if len(tag) != TAG_LEN:
                raise ValueError("La copia cifrada está incompleta.")
            try:
                final_plain = decryptor.finalize_with_tag(tag)
            except InvalidTag as exc:
                raise ValueError("Contraseña incorrecta o copia dañada.") from exc
            if final_plain:
                target.write(final_plain)


def safe_extract(zip_path: Path, destination: Path) -> int:
    """Extrae únicamente rutas relativas y rechaza duplicados o traversal."""
    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve()
    seen = set()
    extracted = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                rel = PurePosixPath(name)
                if not name or rel.is_absolute() or any(part in ("..", "") for part in rel.parts):
                    raise ValueError("La copia contiene una ruta no permitida.")
                if rel.parts and ":" in rel.parts[0]:
                    raise ValueError("La copia contiene una ruta no permitida.")
                normalized = rel.as_posix().rstrip("/")
                if normalized in seen:
                    raise ValueError("La copia contiene rutas duplicadas.")
                seen.add(normalized)
                target = (destination / Path(*rel.parts)).resolve()
                if os.path.commonpath((str(root), str(target))) != str(root):
                    raise ValueError("La copia intenta escribir fuera de la carpeta de destino.")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, length=CHUNK_SIZE)
                extracted += 1
        return extracted
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def is_inside_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False


class VayaBackupApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("VAYA - Copia cifrada segura")
        root.geometry("720x390")
        root.minsize(620, 340)
        root.configure(bg="#101010")

        tk.Label(root, text="VAYA · COPIA CIFRADA", bg="#101010", fg="#ff3838",
                 font=("Consolas", 24, "bold")).pack(pady=(24, 8))
        tk.Label(root, text="Protegé una copia de esta carpeta sin tocar los originales.",
                 bg="#101010", fg="#eeeeee", font=("Consolas", 11)).pack(pady=4)

        panel = tk.Frame(root, bg="#191919", padx=18, pady=14)
        panel.pack(fill="x", padx=28, pady=18)
        tk.Label(panel, text="CARPETA DE ORIGEN (solo esta carpeta y sus subcarpetas):",
                 bg="#191919", fg="#aaaaaa", font=("Consolas", 9, "bold")).pack(anchor="w")
        tk.Label(panel, text=str(ROOT), bg="#191919", fg="#ffffff",
                 font=("Consolas", 9), wraplength=630, justify="left").pack(anchor="w", pady=(6, 0))

        self.status = tk.Label(root, text="Los archivos originales permanecerán intactos.",
                               bg="#101010", fg="#bbbbbb", font=("Consolas", 10), wraplength=650)
        self.status.pack(pady=4)

        buttons = tk.Frame(root, bg="#101010")
        buttons.pack(pady=14)
        self.encrypt_button = tk.Button(
            buttons, text="CREAR COPIA CIFRADA", command=self.create_backup,
            bg="#d92d2d", fg="white", activebackground="#f04444",
            font=("Consolas", 11, "bold"), relief="flat", padx=16, pady=10
        )
        self.encrypt_button.pack(pady=6)
        self.restore_button = tk.Button(
            buttons, text="RESTAURAR COPIA", command=self.restore_backup,
            bg="#333333", fg="white", activebackground="#555555",
            font=("Consolas", 11, "bold"), relief="flat", padx=16, pady=10
        )
        self.restore_button.pack(pady=6)
        tk.Label(root, text="No cifra archivos en el lugar, no los elimina y no bloquea Windows.",
                 bg="#101010", fg="#777777", font=("Consolas", 8)).pack(side="bottom", pady=14)

    def set_busy(self, busy: bool, message: str):
        state = "disabled" if busy else "normal"
        self.encrypt_button.config(state=state)
        self.restore_button.config(state=state)
        self.status.config(text=message)

    def create_backup(self):
        output_name = ROOT.name + "_copia.vayaenc"
        output_text = filedialog.asksaveasfilename(
            title="Guardar copia cifrada fuera de la carpeta de origen",
            initialdir=str(ROOT.parent), initialfile=output_name,
            defaultextension=".vayaenc", filetypes=[("Copia cifrada VAYA", "*.vayaenc")]
        )
        if not output_text:
            return
        output = Path(output_text).resolve()
        if is_inside_root(output):
            messagebox.showerror("Ubicación no permitida",
                                 "Guardá la copia fuera de la carpeta de origen para evitar incluirla en sí misma.")
            return
        if output.exists():
            messagebox.showerror("El archivo ya existe", "Elegí un nombre que todavía no exista.")
            return
        password = simpledialog.askstring("Contraseña", "Elegí una contraseña para la copia:", show="*")
        if password is None:
            return
        if len(password) < 8:
            messagebox.showwarning("Contraseña demasiado corta", "Usá al menos 8 caracteres.")
            return
        confirm = simpledialog.askstring("Confirmar contraseña", "Repetí la contraseña:", show="*")
        if confirm is None:
            return
        if password != confirm:
            messagebox.showerror("No coincide", "Las contraseñas no coinciden.")
            return

        self.set_busy(True, "Preparando y cifrando la copia…")

        def worker():
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(prefix="vaya_", suffix=".zip", delete=False) as tmp:
                    temp_path = Path(tmp.name)
                count = build_zip(temp_path)
                if count == 0:
                    raise ValueError("No se encontraron archivos para incluir en la copia.")
                encrypt_zip(temp_path, output, password)
                self.root.after(0, lambda: self.done_message(
                    f"Copia cifrada creada correctamente.\nArchivos incluidos: {count}\n\nOriginales intactos.\nGuardada en: {output}"
                ))
            except Exception as exc:
                self.root.after(0, lambda err=str(exc): self.error_message(err))
            finally:
                if temp_path:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass

        threading.Thread(target=worker, daemon=True).start()

    def restore_backup(self):
        source_text = filedialog.askopenfilename(
            title="Seleccionar copia cifrada VAYA",
            initialdir=str(ROOT.parent), filetypes=[("Copia cifrada VAYA", "*.vayaenc"), ("Todos los archivos", "*.*")]
        )
        if not source_text:
            return
        encrypted = Path(source_text)
        password = simpledialog.askstring("Contraseña", "Ingresá la contraseña de la copia:", show="*")
        if password is None:
            return
        parent_text = filedialog.askdirectory(title="Elegí dónde crear una carpeta nueva con los archivos restaurados")
        if not parent_text:
            return
        parent = Path(parent_text).resolve()
        destination_base = parent / (encrypted.stem + "_restaurado")
        destination = destination_base
        index = 1
        while destination.exists():
            destination = parent / f"{destination_base.name}_{index}"
            index += 1

        self.set_busy(True, "Verificando la copia y restaurando en una carpeta nueva…")

        def worker():
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(prefix="vaya_restore_", suffix=".zip", delete=False) as tmp:
                    temp_path = Path(tmp.name)
                decrypt_to_zip(encrypted, temp_path, password)
                count = safe_extract(temp_path, destination)
                self.root.after(0, lambda: self.done_message(
                    f"Restauración completada.\nArchivos recuperados: {count}\n\nCarpeta nueva: {destination}"
                ))
            except Exception as exc:
                self.root.after(0, lambda err=str(exc): self.error_message(err))
            finally:
                if temp_path:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass

        threading.Thread(target=worker, daemon=True).start()

    def done_message(self, message: str):
        self.set_busy(False, "Operación terminada.")
        messagebox.showinfo("VAYA", message)

    def error_message(self, message: str):
        self.set_busy(False, "La operación no se pudo completar.")
        messagebox.showerror("VAYA - Error", message)


def main():
    root = tk.Tk()
    VayaBackupApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
