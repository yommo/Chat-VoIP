# Copyright (c) 2025 EndermanPC - Bùi Nguyễn Tấn Sang

import asyncio, os, time, uuid, bcrypt, base64, socketio, mimetypes
import socket
import threading
import sys
import binascii

from aiohttp import web
from pngdb import load_db, save_db

DB_FILE = os.getenv("CHAT_DB_FILE", "chat_db.png")
DB_PASS = os.getenv("CHAT_DB_PASSWORD", "change_me")
RATE_LIMIT_PER_MIN = 60       # WebSocket events per-IP per minute
MAX_BINARY_MB = 10            # Reject larger than this

# --- VoIP specific configurations ---
VOIP_UDP_HOST = os.getenv("VOIP_UDP_HOST", "127.0.0.1") # Default to loopback for local testing
VOIP_UDP_PORT = int(os.getenv("VOIP_UDP_PORT", 10000))
# -------------------------------------------------------------------

# ---- database helpers -----------------------------------------------------

def _load_db():
    try:
        return load_db(DB_FILE, DB_PASS)
    except Exception as e:
        print(f"Error loading database: {e}. Initializing new DB.", file=sys.stderr)
        return {"users": {}, "messages": []}

db = _load_db()

def _save_db():
    try:
        save_db(db, DB_FILE, DB_PASS)
    except Exception as e:
        print(f"Error saving database: {e}", file=sys.stderr)

# ---- simple in‑memory rate‑limiter ---------------------------------------
_calls: dict[tuple[str, int], int] = {}

def ratelimit(ip: str) -> bool:
    now = int(time.time())
    bucket = now // 60  # per‑minute window
    key = (ip, bucket)
    _calls[key] = _calls.get(key, 0) + 1
    # Clean up old buckets to prevent memory leak
    for old_key in list(_calls.keys()):
        if old_key[1] < bucket - 1: # Keep current and previous minute
            del _calls[old_key]
    return _calls[key] <= RATE_LIMIT_PER_MIN

# ---- Socket.IO server -----------------------------------------------------

sio = socketio.AsyncServer(async_mode="aiohttp", cors_allowed_origins="*")
app = web.Application()
sio.attach(app)

# In-memory store for active calls and user sessions
_active_calls: dict[str, str] = {}  # {phone1: phone2, phone2: phone1} for mutual lookup
_user_sessions: dict[str, str] = {} # {phone: sid}

# _voip_participants now stores the *actual UDP address* (ip, port) from where packets are received
# {phone: (udp_ip_from_recvfrom, udp_port_from_recvfrom)}
_voip_participants: dict[str, tuple[str, int]] = {}

# ---- UDP VoIP Server ------------------------------------------------------
_udp_sock: socket.socket | None = None
_udp_server_running = False

def _run_udp_server():
    global _udp_sock, _udp_server_running
    _udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        _udp_sock.bind(("0.0.0.0", VOIP_UDP_PORT)) # Correct binding syntax
        _udp_sock.settimeout(1.0) # Set a timeout to allow checking _udp_server_running
    except OSError as e:
        print(f"Failed to bind UDP socket on port {VOIP_UDP_PORT}: {e}", file=sys.stderr)
        _udp_server_running = False
        return

    print(f"UDP VoIP server listening on 0.0.0.0:{VOIP_UDP_PORT}")
    _udp_server_running = True

    while _udp_server_running:
        try:
            data, addr = _udp_sock.recvfrom(4096) # Max UDP packet size
            # 'addr' is (source_ip, source_port) of the client sending the packet.

            # Determine who sent this packet by matching their source address
            # This mapping needs to be established when the call is accepted/started
            sender_phone = None
            for phone, stored_addr in list(_voip_participants.items()): # Iterate on a copy for safety
                if stored_addr == addr:
                    sender_phone = phone
                    break

            if sender_phone:
                # Find the partner in the call using the bi-directional _active_calls map
                partner_phone = _active_calls.get(sender_phone)
                if partner_phone:
                    partner_addr = _voip_participants.get(partner_phone)
                    if partner_addr:
                        try:
                            _udp_sock.sendto(data, partner_addr)
                        except OSError as e:
                            print(f"UDP send error to {partner_addr}: {e}", file=sys.stderr)
                    else:
                        print(f"Partner {partner_addr} UDP address not found for {addr}", file=sys.stderr)
                else:
                    print(f"No active call found for {addr}", file=sys.stderr)
            else:
                print(f"Unidentified UDP packet from {addr}", file=sys.stderr)

        except socket.timeout:
            continue # Just check the running flag again after timeout
        except Exception as e:
            print(f"UDP server error: {e}", file=sys.stderr)
            # Consider if a critical error should stop the server or just log
            break
    print("UDP VoIP server stopped.")

def _start_udp_server_thread():
    thread = threading.Thread(target=_run_udp_server, daemon=True)
    thread.start()

def _stop_udp_server():
    global _udp_server_running
    _udp_server_running = False
    if _udp_sock:
        print("Closing UDP socket...")
        _udp_sock.close()
        _udp_sock = None

# ---------------------------------------------------------------------------

@sio.event
async def connect(sid, environ):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many requests. Please wait."}, to=sid)
        await sio.disconnect(sid) # Disconnect if rate-limited
        return
    print(f"New WebSocket connection from: {peer_ip}, SID: {sid}")

@sio.event
async def auth(sid, data):
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))

    if not phone or not password:
        await sio.emit("auth_error", {"error": "Missing credentials"}, to=sid)
        await sio.disconnect(sid)
        return

    user = db["users"].get(phone)
    if user:
        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            await sio.emit("auth_error", {"error": "Invalid phone/password"}, to=sid)
            await sio.disconnect(sid)
            return
    else:
        # Self‑service registration
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db["users"][phone] = {"password": pwd_hash, "created": time.time()}
        _save_db()
        print(f"Registered new user {phone}")

    _user_sessions[phone] = sid # Store SID for the authenticated user
    await sio.enter_room(sid, phone)
    await sio.emit("auth_ok", {}, to=sid)
    # Inform other users about this user coming online (if they are observing status)
    for other_phone, other_sid in _user_sessions.items():
        if other_phone != phone:
            await sio.emit("user_status", {"statuses": {phone: "Online"}}, to=other_sid)


@sio.event
async def load_messages(sid, data):
    user = data.get("phone")
    # Ensure user is authenticated and session exists for this sid
    if _user_sessions.get(user) != sid:
        await sio.emit("error", {"error": "Unauthorized message load request"}, to=sid)
        await sio.disconnect(sid)
        return

    if user not in db["users"]:
        await sio.emit("error", {"error": f"User {user} not found"}, to=sid)
        return
    user_msgs = [m for m in db["messages"] if m["from"] == user or m["to"] == user]
    await sio.emit("message_history", user_msgs, to=sid)

@sio.event
async def check_status(sid, data):
    requester_phone = next((phone for phone, session_sid in _user_sessions.items() if session_sid == sid), None)
    if not requester_phone:
        await sio.emit("error", {"error": "Authentication required for status check."}, to=sid)
        await sio.disconnect(sid)
        return

    users_to_check = data.get("users", [])
    status_map = {}

    for user_phone in users_to_check:
        status_map[user_phone] = "Online" if user_phone in _user_sessions else "Offline"

    await sio.emit("user_status", {"statuses": status_map}, to=sid)

@sio.event
async def send_text(sid, data):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many requests. Please wait."}, to=sid)
        return

    sender = data.get("from")
    dst = data.get("to")
    text = str(data.get("text", ""))[:4096] # Limit text length

    # Validate sender and recipient
    if _user_sessions.get(sender) != sid:
        await sio.emit("error", {"error": "Unauthorized sender."}, to=sid)
        return
    if dst not in db["users"]:
        await sio.emit("error", {"error": f"Recipient user {dst} not found."}, to=sid)
        return

    msg = {
        "id": str(uuid.uuid4()),
        "from": sender,
        "to": dst,
        "text": text,
        "ts": time.time(),
        "type": "text",
    }
    db["messages"].append(msg)
    _save_db()
    # Only emit to recipient if online, otherwise message will be loaded from history
    if dst in _user_sessions:
        await sio.emit("recv_text", msg, room=dst)
    await sio.emit("info", {"message": f"Message sent to {dst}."}) # Confirm send to sender

@sio.event
async def send_file(sid, data: dict):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many requests. Please wait."}, to=sid)
        return
    
    sender = data.get("from")
    dst = data.get("to")
    msg_display = data.get("msg") # The display message for the file
    fname = data.get("filename", "file.bin")
    mime = data.get("mimetype") or mimetypes.guess_type(fname)[0] or "application/octet-stream"
    b64_string = data.get("b64_string")

    # Validate sender and recipient
    if _user_sessions.get(sender) != sid:
        await sio.emit("error", {"error": "Unauthorized sender."}, to=sid)
        return
    if dst not in db["users"]:
        await sio.emit("error", {"error": f"Recipient user {dst} not found."}, to=sid)
        return
    if not b64_string:
        await sio.emit("error", {"error": "Missing file data."}, to=sid)
        return

    try:
        file_bytes = base64.b64decode(b64_string)
    except binascii.Error: # Catch specific base64 decoding error
        await sio.emit("error", {"error": "Invalid base64 string provided."}, to=sid)
        return
    except Exception as e:
        await sio.emit("error", {"error": f"Error decoding file data: {e}"}, to=sid)
        return

    if len(file_bytes) > MAX_BINARY_MB * 1024 * 1024:
        await sio.emit("error", {"error": f"File exceeds size limit ({MAX_BINARY_MB} MB)."}, to=sid)
        return

    msg_id = str(uuid.uuid4())
    meta_out = {
        "id": msg_id,
        "from": sender,
        "to": dst,
        "msg": msg_display, # Store the display message in metadata
        "filename": fname,
        "mimetype": mime,
        "size": len(file_bytes),
        "ts": time.time(),
        "type": "file",
    }
    db["messages"].append(meta_out)
    _save_db()

    # Only emit file data if recipient is online
    if dst in _user_sessions:
        await sio.emit("recv_file", {"meta": meta_out, "b64_string": b64_string}, room=dst)
    await sio.emit("info", {"message": f"File '{fname}' sent to {dst}."}) # Confirm send to sender


@sio.event
async def start_call(sid, data):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many call requests. Please wait."}, to=sid)
        return
    
    caller = data.get("from")
    callee = data.get("to")
    
    # Authenticate caller
    if _user_sessions.get(caller) != sid:
        await sio.emit("error", {"error": "Unauthorized caller."}, to=sid)
        return

    if callee not in _user_sessions:
        await sio.emit("error", {"error": f"User {callee} is offline."}, to=sid)
        return
    
    # Check if either party is already in a call
    if caller in _active_calls or callee in _active_calls.values():
        await sio.emit("error", {"error": f"You or {callee} are already in a call."}, to=sid)
        return

    msg_text = data.get("msg")
    client_udp_port = data.get("udp_port")
    client_ip = data.get("client_ip") or sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")

    if client_udp_port:
        _voip_participants[caller] = (client_ip, client_udp_port)
        print(f"SID: {sid} (caller) registered VoIP endpoint: {client_ip}:{client_udp_port}")
    else:
        await sio.emit("error", {"error": "Caller UDP port not provided."}, to=sid)
        return

    _active_calls[caller] = callee
    _active_calls[callee] = caller # Bi-directional tracking

    callee_sid = _user_sessions[callee]
    msg_id = str(uuid.uuid4())
    call_msg = {
        "id":       msg_id,
        "from":     caller,
        "to":       callee,
        "msg":      msg_text, # Use 'text' key for display message
        "ts":       time.time(),
        "type":     "call",
    }
    db["messages"].append(call_msg)
    _save_db()
    await sio.emit("incoming_call", {"from": caller, "call_msg": call_msg}, to=callee_sid)
    await sio.emit("info", {"message": f"Calling {callee}..."})

@sio.event
async def accept_call(sid, data):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many call requests. Please wait."}, to=sid)
        return
    
    callee = next((phone for phone, session_sid in _user_sessions.items() if session_sid == sid), None)
    if not callee:
        await sio.emit("error", {"error": "Authentication required to accept call."}, to=sid)
        return

    caller = _active_calls.get(callee)
    if not caller:
        await sio.emit("error", {"error": "No pending call to accept from you."}, to=sid)
        return
    
    # Ensure caller is still in an active call with this callee
    if _active_calls.get(caller) != callee:
        await sio.emit("error", {"error": "Call state mismatch. Call may have ended."}, to=sid)
        # Attempt to clean up stale entry for callee if any
        _active_calls.pop(callee, None)
        return

    client_udp_port = data.get("udp_port")
    client_ip = data.get("client_ip") or sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")

    if client_udp_port:
        _voip_participants[callee] = (client_ip, client_udp_port)
        print(f"SID: {sid} (callee) registered VoIP endpoint: {client_ip}:{client_udp_port}")
    else:
        await sio.emit("error", {"error": "Callee UDP port not provided."}, to=sid)
        return

    caller_sid = _user_sessions.get(caller)
    
    # Ensure both participants have registered their UDP endpoints
    if caller not in _voip_participants or callee not in _voip_participants:
        await sio.emit("error", {"error": "Both parties must register VoIP UDP endpoints."}, to=sid)
        # Attempt to clean up partially established call
        _active_calls.pop(caller, None)
        _active_calls.pop(callee, None)
        _voip_participants.pop(caller, None)
        _voip_participants.pop(callee, None)
        return

    # Inform both caller and callee about the VoIP relay server details
    # The client will use VOIP_UDP_HOST:VOIP_UDP_PORT to send voice data
    # and the server will relay it based on their registered source IP/port in _voip_participants.
    await sio.emit("call_accepted", {
        "partner": callee,
        "voip_server_ip": VOIP_UDP_HOST,
        "voip_server_port": VOIP_UDP_PORT,
    }, to=caller_sid)

    await sio.emit("call_accepted", {
        "partner": caller,
        "voip_server_ip": VOIP_UDP_HOST,
        "voip_server_port": VOIP_UDP_PORT,
    }, to=sid)
    print(f"Call by SID: {sid} established.")


@sio.event
async def reject_call(sid, data):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many requests. Please wait."}, to=sid)
        return

    callee = next((phone for phone, session_sid in _user_sessions.items() if session_sid == sid), None)
    if not callee:
        await sio.emit("error", {"error": "Authentication required to reject call."}, to=sid)
        return

    # Remove call from active calls from callee's perspective
    caller = _active_calls.pop(callee, None)
    if caller:
        _active_calls.pop(caller, None) # Remove from caller's perspective too
        _voip_participants.pop(caller, None) # Remove caller from VoIP participants
        _voip_participants.pop(callee, None) # Remove callee from VoIP participants

        caller_sid = _user_sessions.get(caller)
        if caller_sid:
            await sio.emit("call_rejected", {"partner": callee}, to=caller_sid)
            print(f"Call from SID: {sid} rejected.")
    await sio.emit("info", {"message": "Call rejected."})

@sio.event
async def end_call(sid, data):
    peer_ip = sio.get_environ(sid).get("REMOTE_ADDR", "0.0.0.0")
    if not ratelimit(peer_ip):
        await sio.emit("error", {"error": "Too many requests. Please wait."}, to=sid)
        return

    sender = next((phone for phone, session_sid in _user_sessions.items() if session_sid == sid), None)
    if not sender:
        await sio.emit("error", {"error": "Authentication required to end call."}, to=sid)
        return

    reason = data.get("reason", "ended")

    # Find the partner of the sender
    partner = _active_calls.pop(sender, None)
    if partner:
        _active_calls.pop(partner, None) # Remove from partner's perspective
        
        # Remove from VoIP participants
        _voip_participants.pop(sender, None)
        _voip_participants.pop(partner, None)

        partner_sid = _user_sessions.get(partner)
        if partner_sid:
            await sio.emit("call_end", {"reason": "partner disconnected"}, to=partner_sid)
            print(f"Call by SID: {sid} ended.")
    
    await sio.emit("call_end", {"reason": reason}, to=sid)
    print(f"Call for SID: {sid} ended with reason: {reason}.")


@sio.event
async def disconnect(sid):
    print(f"Disconnected SID: {sid}")
    disconnected_user_phone = None
    # Find the phone number associated with the disconnected SID
    for phone, session_sid in list(_user_sessions.items()): # Use list to modify dict during iteration
        if session_sid == sid:
            disconnected_user_phone = phone
            del _user_sessions[phone]
            break

    if disconnected_user_phone:
        # Inform other users that this user is now offline
        for other_phone, other_sid in _user_sessions.items():
            await sio.emit("user_status", {"statuses": {disconnected_user_phone: "Offline"}}, to=other_sid)

        # Check if the disconnected user was in a call
        partner = _active_calls.pop(disconnected_user_phone, None)
        if partner:
            # If partner exists, remove call from partner's side and notify
            _active_calls.pop(partner, None)
            _voip_participants.pop(disconnected_user_phone, None)
            _voip_participants.pop(partner, None) # Ensure partner's VoIP state is cleaned too

            partner_sid = _user_sessions.get(partner)
            if partner_sid:
                await sio.emit("call_end", {"reason": "partner disconnected"}, to=partner_sid)
                print(f"Call with SID: {sid} ended because other disconnected.")

if __name__ == "__main__":
    _start_udp_server_thread()
    try:
        web.run_app(app, port=5000)
    finally:
        # Ensure UDP server stops on application exit
        _stop_udp_server()