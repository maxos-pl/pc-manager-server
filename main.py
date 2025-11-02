import os
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Depends
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import databases
import sqlalchemy
import json
import socket
import pathlib

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./db.sqlite3")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change_me")
DOWNLOAD_FOLDER = os.environ.get("DOWNLOAD_FOLDER", "./downloads")

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

computers = sqlalchemy.Table(
    "computers",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("pc_id", sqlalchemy.String, unique=True, index=True),
    sqlalchemy.Column("room", sqlalchemy.String),
    sqlalchemy.Column("mac", sqlalchemy.String, nullable=True),
    sqlalchemy.Column("ip", sqlalchemy.String, nullable=True),
    sqlalchemy.Column("token", sqlalchemy.String),
    sqlalchemy.Column("status", sqlalchemy.String, default="offline"),
    sqlalchemy.Column("last_seen", sqlalchemy.DateTime, nullable=True),
    sqlalchemy.Column("blocked", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, server_default=sqlalchemy.text("CURRENT_TIMESTAMP"))
)

commands = sqlalchemy.Table(
    "commands",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("pc_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("cmd_type", sqlalchemy.String),
    sqlalchemy.Column("payload", sqlalchemy.JSON, nullable=True),
    sqlalchemy.Column("status", sqlalchemy.String, default="pending", index=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, server_default=sqlalchemy.text("CURRENT_TIMESTAMP"))
)

engine = sqlalchemy.create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
metadata.create_all(engine)

app = FastAPI(title="PC Manager")

# serve downloads folder
pathlib.Path(DOWNLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
app.mount("/downloads", StaticFiles(directory=DOWNLOAD_FOLDER), name="downloads")

class RegisterIn(BaseModel):
    pc_id: str
    room: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    token: str

class PollOut(BaseModel):
    commands: List[dict]

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/register")
async def register(data: RegisterIn):
    q = computers.select().where(computers.c.pc_id == data.pc_id)
    existing = await database.fetch_one(q)
    now = datetime.utcnow()
    if existing:
        await database.execute(
            computers.update().where(computers.c.pc_id==data.pc_id).values(
                ip=data.ip, mac=data.mac, token=data.token, last_seen=now, status="online", room=data.room
            )
        )
        return {"status":"updated"}
    else:
        await database.execute(
            computers.insert().values(pc_id=data.pc_id, room=data.room, mac=data.mac, ip=data.ip, token=data.token, status="online", last_seen=now)
        )
        return {"status":"registered"}

@app.get("/poll/{pc_id}", response_model=PollOut)
async def poll(pc_id: str, x_agent_token: Optional[str] = Header(None)):
    q = computers.select().where(computers.c.pc_id==pc_id)
    row = await database.fetch_one(q)
    if not row:
        raise HTTPException(404, "pc not found")
    if x_agent_token != row["token"]:
        raise HTTPException(403, "bad token")
    # mark last seen and online
    await database.execute(computers.update().where(computers.c.pc_id==pc_id).values(last_seen=datetime.utcnow(), status="online"))
    q2 = commands.select().where((commands.c.pc_id==pc_id) & (commands.c.status=="pending"))
    rows = await database.fetch_all(q2)
    cmd_list = []
    for r in rows:
        cmd_list.append({"id": r["id"], "cmd_type": r["cmd_type"], "payload": r["payload"]})
        await database.execute(commands.update().where(commands.c.id==r["id"]).values(status="sent"))
    return {"commands": cmd_list}

@app.post("/command")
async def create_command(pc_id: str, cmd_type: str, payload: Optional[dict] = None, x_admin_key: Optional[str] = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    # ensure pc exists
    q = computers.select().where(computers.c.pc_id==pc_id)
    if not await database.fetch_one(q):
        raise HTTPException(404, "pc not found")
    await database.execute(commands.insert().values(pc_id=pc_id, cmd_type=cmd_type, payload=payload or {}, status="pending"))
    return {"status":"queued"}

@app.post("/report_result/{command_id}")
async def report_result(command_id: int, result: dict, x_agent_token: Optional[str] = Header(None)):
    # For simplicity store result by updating command.status -> done and print to stdout
    q = commands.select().where(commands.c.id==command_id)
    row = await database.fetch_one(q)
    if not row:
        raise HTTPException(404, "command not found")
    # verify token from associated pc
    qpc = computers.select().where(computers.c.pc_id==row["pc_id"])
    pc = await database.fetch_one(qpc)
    if x_agent_token != pc["token"]:
        raise HTTPException(403, "bad token")
    await database.execute(commands.update().where(commands.c.id==command_id).values(status="done"))
    print(f"Result for command {command_id}: {result}")
    return {"ok": True}

@app.get("/version")
async def version():
    # Reads version.json in downloads folder if exists
    ver_file = pathlib.Path(DOWNLOAD_FOLDER) / "version.json"
    if ver_file.exists():
        return json.loads(ver_file.read_text(encoding="utf-8"))
    return {"version": "0.0.0", "url": ""}

@app.post("/upload_binary")
async def upload_binary(file: UploadFile = File(...), x_admin_key: Optional[str] = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    contents = await file.read()
    # keep provided filename and write into downloads folder
    dest = pathlib.Path(DOWNLOAD_FOLDER) / file.filename
    dest.write_bytes(contents)
    return {"ok": True, "path": f"/downloads/{file.filename}"}

@app.post("/set_version")
async def set_version(version: str, filename: str, x_admin_key: Optional[str] = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    # check file existence
    fpath = pathlib.Path(DOWNLOAD_FOLDER) / filename
    if not fpath.exists():
        raise HTTPException(404, "file not found")
    version_data = {"version": version, "url": f"{get_base_url()}/downloads/{filename}"}
    (pathlib.Path(DOWNLOAD_FOLDER) / "version.json").write_text(json.dumps(version_data), encoding="utf-8")
    return {"ok": True, "version": version_data}

def get_base_url():
    # tries to build base url from environment or socket
    base = os.environ.get("BASE_URL")
    if base:
        return base.rstrip("/")
    # fallback (not perfect when behind proxy)
    host = socket.gethostname()
    return f"http://{host}"

# Simple health
@app.get("/health")
async def health():
    return {"ok": True}
