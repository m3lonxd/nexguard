import argparse
import getpass
import sys

from . import config, db, security


def create_admin(username: str) -> int:
    db.init()
    password = getpass.getpass("Parola (en az 12 karakter): ")
    if password != getpass.getpass("Parola (tekrar): "):
        print("Parolalar eşleşmiyor.", file=sys.stderr)
        return 1
    try:
        pw_hash = security.hash_password(password)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    with db.session() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?) "
            "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
            (username, pw_hash),
        )
    print(f"Kullanıcı '{username}' hazır.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="nexguard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="Paneli başlat")
    adm = sub.add_parser("create-admin", help="Yönetici oluştur / parolasını sıfırla")
    adm.add_argument("username")
    args = parser.parse_args()
    if args.cmd == "create-admin":
        return create_admin(args.username)
    import uvicorn
    from .app import create_app
    uvicorn.run(create_app(), host=config.HOST, port=config.PORT, proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
