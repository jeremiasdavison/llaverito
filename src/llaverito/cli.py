import argparse
import base64
import getpass
import os
import sys

from sqlalchemy import select

from .config import ConfigError, Settings, get_settings
from .models import User
from .runtime import build_runtime
from .security import hash_password


def gen_key() -> None:
    print(base64.urlsafe_b64encode(os.urandom(32)).decode())


def create_admin(email: str, name: str, password: str | None) -> None:
    rt = build_runtime(get_settings())
    pw = password or getpass.getpass("Contraseña (mín. 12 caracteres): ")
    with rt.session() as s:
        email = email.strip().lower()
        if s.scalar(select(User.id).where(User.email == email)):
            sys.exit(f"Ya existe un usuario con el email {email}")
        s.add(User(email=email, name=name, password_hash=hash_password(pw), role="admin"))
    print(f"Administrador {email} creado.")


def serve(host: str, port: int) -> None:
    import uvicorn

    uvicorn.run("llaverito.app:create_app", factory=True, host=host, port=port, proxy_headers=False)


def main() -> None:
    parser = argparse.ArgumentParser(prog="llaverito")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key", help="Genera una clave maestra (KEK) nueva")
    p = sub.add_parser("create-admin", help="Crea un usuario administrador")
    p.add_argument("--email", required=True)
    p.add_argument("--name", default="Administrador")
    p.add_argument("--password", help="Si se omite, se pide por teclado")
    p = sub.add_parser("serve", help="Levanta el servidor")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        if args.cmd == "gen-key":
            gen_key()
        elif args.cmd == "create-admin":
            create_admin(args.email, args.name, args.password)
        else:
            Settings().load_kek()  # falla rápido si no hay clave maestra
            serve(args.host, args.port)
    except ConfigError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
