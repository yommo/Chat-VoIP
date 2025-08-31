# Copyright (c) 2025 EndermanPC - Bùi Nguyễn Tấn Sang

import os
import sys
import threading
import queue
import time
import curses
import socketio
import base64
import mimetypes
import uuid
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib

# VoIP imports
import socket
import numpy as np
import sounddevice as sd
import noisereduce as nr

# ---------- CONFIG ----------
SERVER    = os.getenv("CHAT_SERVER_URL", "http://localhost:5000")
PHONE    = os.getenv("CHAT_CLIENT_PHONE") or input("Phone (+84…): ").strip()
PASSWORD = os.getenv("CHAT_CLIENT_PASS") or input("Password: ").strip()
SAVE_DIR = os.getenv("CHAT_DOWNLOAD_DIR", ".")
MAX_SHOW = 500  # max messages per chat kept in memory
hashed = hashlib.sha256(PASSWORD.encode()).digest()  # 32 bytes
ENCRYPTION_KEY = base64.urlsafe_b64encode(hashed)
fernet = Fernet(ENCRYPTION_KEY)

# VoIP Config
SAMPLE_RATE = 48_000  # Hz
CHUNK       = 960     # ≈20 ms @ 48 kHz (16-bit mono → 1,920 bytes)
# CLIENT_UDP_PORT_RANGE = (10000, 10100) # Expanded range for client to pick a UDP port - Not currently used for explicit binding.
# Noise Reducing Config
NOISE_REDUCTION_ENABLED = os.getenv("NOISE_REDUCTION_ENABLED", "True").lower() == "true" # Parse as boolean
NOISE_REDUCTION_STRENGTH = float(os.getenv("NOISE_REDUCTION_STRENGTH", 1.0))
# ----------------------------

io = socketio.Client()
message_queues: dict[str, list[tuple[str,str,str]]] = {}  # {phone: [(direction,msg,time)]}
chats: list[str] = []
current_chat: str | None = None
user_online_status: dict[str, str] = {}
in_call: bool = False
call_partner: str | None = None
_voip_sock: socket.socket | None = None
_voip_threads_stop_event: threading.Event | None = None
_play_q: queue.Queue[bytes] = queue.Queue(maxsize=50)  # jitter buffer

lock   = threading.Lock()
event_q = queue.Queue()  # (type, payload)

# ===== Socket.IO Handlers =====
@io.event
def connect():
    io.emit("auth", {"phone": PHONE, "password": PASSWORD})

@io.event
def auth_ok(_):
    io.emit("load_messages", {"phone": PHONE})
    # Request status for all known users after authentication
    _request_all_known_user_statuses()

@io.event
def auth_error(data):
    event_q.put(("error", data.get("error")))
    io.disconnect()

@io.event
def error(data):
    event_q.put(("error", data.get("error")))

@io.event
def message_history(msg_list):
    global current_chat
    with lock:
        for m in msg_list:
            other = m["from"] if m["from"] != PHONE else m["to"]
            if other not in message_queues:
                message_queues[other] = []
                chats.append(other)
            direction = "←" if m["from"] != PHONE else "→"
            ts = _fmt_ts(m.get("ts")) # Use _fmt_ts for consistency
            txt = m.get("text", "") or m.get("msg", "") # Default to empty string if text is missing
            try:
                if txt: # Only try to decrypt if there's text
                    txt = fernet.decrypt(txt.encode()).decode()
            except Exception: # Catch any decryption errors
                txt = "[Decryption Error or Unsupported]" if txt else "[Unsupported]" # More informative message
            message_queues[other].append((direction, txt, ts))
        if chats:
            current_chat = chats[0]

    _request_all_known_user_statuses() # Already called in auth_ok, but keeping for robustness
    event_q.put(("ready", None))

@io.on("user_status")
def on_user_status(data):
    with lock:
        new_statuses = data.get("statuses", {})
        user_online_status.update(new_statuses)
    event_q.put(("update_status", None)) # Notify UI to redraw statuses

@io.on("recv_text")
def on_recv_text(data):
    other = data.get("from")
    _ensure_chat(other)
    ts = _fmt_ts(data.get("ts"))
    try:
        msg = fernet.decrypt(data.get("text").encode()).decode()
    except Exception:
        msg = "[Decryption Error]"
    with lock:
        message_queues[other].append(("←", msg, ts))
        _trim(other)
    event_q.put(("update", None))

@io.on("recv_file")
def on_recv_file(data):
    meta = data.get("meta"); b64 = data.get("b64_string")
    other = meta.get("from")
    _ensure_chat(other)
    file_bytes = base64.b64decode(b64)
    # Use uuid for unique file names in case of same filename from different senders
    fname_local = os.path.join(SAVE_DIR, f"received_{meta.get('id', str(uuid.uuid4()))}_{meta.get('filename', 'unknown_file')}")
    try:
        os.makedirs(SAVE_DIR, exist_ok=True) # Ensure save directory exists
        with open(fname_local, "wb") as f:
            f.write(file_bytes)
        display_txt = f"[File] {meta.get('filename', 'unknown_file')} saved as {os.path.basename(fname_local)}"
    except Exception as e:
        display_txt = f"[File] Save failed: {e}"
        fname_local = "[File] Save failed" # For consistency in message list

    file_msg = meta.get("msg")
    file_msg = fernet.decrypt(file_msg.encode()).decode()
    ts = _fmt_ts(meta.get("ts"))
    with lock:
        # Message from server about the file transfer
        if file_msg:
            message_queues[other].append(("←", file_msg, ts))
            _trim(other)
        # Client-side message about file saving
        message_queues[other].append(("←", display_txt, ts))
        _trim(other)
    event_q.put(("update", None))

@io.on("incoming_call")
def on_incoming_call(data):
    caller = data.get("from")
    call_msg = data.get("call_msg")
    call_msg = fernet.decrypt(call_msg.encode()).decode()
    sender = call_msg["from"] # This should be the same as 'caller'
    ts = _fmt_ts(call_msg["ts"])
    with lock:
        message_queues[sender].append(("←", call_msg.get("text"), ts))
        _trim(sender)
    event_q.put(("incoming_call", caller))

@io.on("call_accepted")
def on_call_accepted(data):
    global in_call, call_partner
    partner = data.get("partner")
    voip_server_ip = data.get("voip_server_ip")
    voip_server_port = data.get("voip_server_port")

    # Ensure voip_server_ip and voip_server_port is set before starting VoIP session
    if voip_server_ip is None or voip_server_port is None:
        event_q.put(("error", "VoIP server ip or port is not available. Cannot start VoIP session."))
        return

    event_q.put(("info", f"Call with {partner} accepted! Connecting to VoIP..."))
    in_call = True
    call_partner = partner
    _start_voip_session(voip_server_ip, voip_server_port)

@io.on("call_rejected")
def on_call_rejected(data):
    partner = data.get("partner")
    event_q.put(("info", f"Call with {partner} rejected."))
    _end_voip_session()
    global in_call, call_partner
    in_call = False
    call_partner = None

@io.on("call_end")
def on_call_end(data):
    global in_call, call_partner
    reason = data.get("reason", "ended")
    event_q.put(("info", f"Call {reason}."))
    in_call = False
    call_partner = None
    _end_voip_session()


# ===== Helpers =====

def _fmt_ts(ts_str):
    if not ts_str:
        return datetime.now().strftime("%H:%M")
    try:
        # Prioritize ISO format parsing as it's common for server timestamps
        if isinstance(ts_str, str):
            # Handle potential milliseconds by stripping them before parsing
            if '.' in ts_str:
                ts_str_no_ms = ts_str.split('.')[0]
                dt_obj = datetime.fromisoformat(ts_str_no_ms)
            else:
                dt_obj = datetime.fromisoformat(ts_str)
            return dt_obj.strftime("%H:%M")
        # Fallback to timestamp if it's a number
        return datetime.fromtimestamp(float(ts_str)).strftime("%H:%M")
    except Exception:
        return "" # Return empty string on parsing error

def _ensure_chat(phone):
    with lock:
        if phone not in message_queues:
            message_queues[phone] = []
            chats.append(phone)

def _trim(phone):
    if len(message_queues[phone]) > MAX_SHOW:
        message_queues[phone] = message_queues[phone][-MAX_SHOW:]

def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) # Connect to a public IP to get local IP
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1" # Fallback to loopback if no external connection
    finally:
        s.close()
    return ip

def _get_voip_socket():
    global _voip_sock
    if _voip_sock is None:
        _voip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _voip_sock.bind(("", 0)) # OS provides a random available port
        _voip_sock.setblocking(False) # Set non-blocking immediately
    return _voip_sock

# VoIP session management
def _start_voip_session(server_ip: str, server_port: int):
    global _voip_sock, _voip_threads_stop_event, _play_q

    _voip_threads_stop_event = threading.Event()
    _play_q = queue.Queue(maxsize=50) # Reset jitter buffer for new call

    _sock = _get_voip_socket() # Re-use or create if not exists
    _sock.connect((server_ip, server_port)) # Connect to the server's VoIP relay port
    # _voip_sock.setblocking(False) # Already set in _get_voip_socket
    _sock.send(b"\0") # initial ping

    def capture():
        _noise_sample_collected = False
        _noise_profile = None

        # Buffer to accumulate enough noise for profiling
        noise_buffer = np.array([], dtype=np.int16)

        def cb(indata, frames, time, status):
            nonlocal _noise_sample_collected, _noise_profile, noise_buffer

            if status:
                print(f"Sounddevice input status: {status}", file=sys.stderr)

            audio_data = np.frombuffer(indata, dtype=np.int16).flatten()

            if NOISE_REDUCTION_ENABLED:
                if not _noise_sample_collected:
                    noise_buffer = np.concatenate((noise_buffer, audio_data))
                    if len(noise_buffer) >= SAMPLE_RATE: # Collect 1 second of noise
                        print("Collecting initial noise sample for reduction...", file=sys.stderr)
                        _noise_profile = noise_buffer[:SAMPLE_RATE]
                        _noise_sample_collected = True
                        print("Noise sample collected.", file=sys.stderr)
                        # Process the current chunk after noise profile is ready
                        processed_data = nr.reduce_noise(
                            audio_data=audio_data,
                            sr=SAMPLE_RATE,
                            y_noise=_noise_profile,
                            prop_decrease=NOISE_REDUCTION_STRENGTH
                        )
                        processed_data = processed_data.astype(np.int16)
                    else:
                        processed_data = audio_data # Pass original data until profile is ready
                else:
                    try:
                        processed_data = nr.reduce_noise(
                            audio_data=audio_data,
                            sr=SAMPLE_RATE,
                            y_noise=_noise_profile,
                            prop_decrease=NOISE_REDUCTION_STRENGTH
                        )
                        processed_data = processed_data.astype(np.int16)
                    except Exception as e:
                        print(f"Noise reduction error: {e}", file=sys.stderr)
                        processed_data = audio_data # Fallback to original if error
            else:
                processed_data = audio_data

            try:
                if _voip_sock and not _voip_threads_stop_event.is_set():
                    _voip_sock.send(processed_data.tobytes()) # Gửi dữ liệu đã xử lý
            except OSError:
                pass # drop if socket send buffer full

        with sd.InputStream(channels=1,
                            samplerate=SAMPLE_RATE,
                            blocksize=CHUNK,
                            dtype="int16",
                            callback=cb):
            _voip_threads_stop_event.wait() # run until event is set

    def receive():
        while not _voip_threads_stop_event.is_set():
            try:
                if _voip_sock:
                    data = _voip_sock.recv(CHUNK * 2) # Receive up to CHUNK * 2 bytes
                    if data:
                        # Pad or truncate to ensure correct size for numpy.frombuffer
                        if len(data) < CHUNK * 2:
                            data = data + b"\x00" * (CHUNK * 2 - len(data))
                        elif len(data) > CHUNK * 2:
                            data = data[:CHUNK * 2]
                        _play_q.put_nowait(data)
            except BlockingIOError:
                time.sleep(0.001) # Small delay to prevent busy-waiting
                continue
            except Exception as e:
                print(f"VoIP receive error: {e}", file=sys.stderr)
                break

    def play():
        def cb(outdata, frames, time, status):
            if status:
                print(f"Sounddevice output status: {status}", file=sys.stderr)
            try:
                chunk = _play_q.get_nowait()
            except queue.Empty:
                chunk = b"\x00" * CHUNK * 2 # silence (underrun)
            outdata[:] = np.frombuffer(chunk, dtype=np.int16).reshape(-1, 1)

        with sd.OutputStream(channels=1,
                              samplerate=SAMPLE_RATE,
                              blocksize=CHUNK,
                              dtype="int16",
                              callback=cb):
            _voip_threads_stop_event.wait() # run until event is set

    threading.Thread(target=capture, daemon=True).start()
    threading.Thread(target=receive, daemon=True).start()
    threading.Thread(target=play, daemon=True).start()
    event_q.put(("info", "On call..."))


def _end_voip_session():
    global _voip_sock, _voip_threads_stop_event
    if _voip_threads_stop_event:
        _voip_threads_stop_event.set() # Signal threads to stop
    # Give threads a moment to finish before closing socket
    time.sleep(0.1)
    if _voip_sock:
        _voip_sock.close()
        _voip_sock = None
    event_q.put(("info", "Call ended."))

# ===== UI Drawing =====

def init_windows(stdscr):
    h, w = stdscr.getmaxyx()
    chat_w   = max(25, w // 5)
    win_chats = stdscr.derwin(h-2, chat_w, 0, 0)
    win_msgs  = stdscr.derwin(h-3, w-chat_w-1, 0, chat_w+1)
    win_input = stdscr.derwin(3, w, h-3, 0)
    win_input.nodelay(True)
    return win_chats, win_msgs, win_input


def draw_chats(win, selected):
    win.erase(); win.border(); win.addstr(0, 2, " Chats ")
    max_h, max_w = win.getmaxyx()
    for idx, chat in enumerate(chats[:max_h-2]):
        attr = curses.A_REVERSE if chat == selected else curses.A_NORMAL
        status_char = ""
        if chat in user_online_status:
            status_char = "•" if user_online_status[chat] == "Online" else "○"
        display_name = f"{status_char} {chat}"
        win.addstr(1+idx, 1, display_name[:max_w-2], attr)
    win.refresh()


def draw_msgs(win, chat):
    win.erase(); win.border()

    title = " No chat "
    if chat:
        status_text = ""
        if chat in user_online_status:
            status_text = user_online_status[chat]
        title = f" Chat with {chat} ({status_text}) " if status_text else f" Chat with {chat} "

    win.addstr(0, 2, title)
    if chat:
        msgs = message_queues.get(chat, [])
        max_h, max_w = win.getmaxyx()
        start_idx = max(0, len(msgs) - (max_h - 2))
        for i, (d, text, ts) in enumerate(msgs[start_idx:]):
            prefix = f"{d}{ts} "
            display_text = (prefix + text)[:max_w-2]
            try:
                win.addstr(1+i, 1, display_text)
            except curses.error:
                win.addstr(1+i, 1, display_text[:max_w-3] + "…")
    win.refresh()


def draw_input(win, buf, status):
    win.erase(); win.border()
    max_h, max_w = win.getmaxyx()
    input_line = f"> {buf}"[:max_w-2] # Truncate input buffer if too long
    win.addstr(1, 1, input_line)
    # Clear to end of line to remove previous longer input
    win.clrtoeol()
    # Position status message appropriately
    status_display = status[:max_w-2] # Truncate status if too long
    win.addstr(1, max_w-len(status_display)-2, status_display, curses.A_DIM)
    win.refresh()

# ===== Main loop =====

def ui_loop(stdscr):
    global _voip_sock, current_chat, in_call, call_partner
    curses.curs_set(1) # Make cursor visible
    stdscr.nodelay(True) # Make getch non-blocking for main loop
    win_chats, win_msgs, win_input = init_windows(stdscr)
    input_buf = ""
    status = "Loading..."
    incoming_call_prompt = None

    while True:
        try:
            # Process all events in the queue
            while True:
                evt_tuple = event_q.get_nowait()
                evt_type, payload = evt_tuple[0], evt_tuple[1]

                if evt_type == "error":
                    status = f"Error: {payload}"
                elif evt_type == "info":
                    status = f"Info: {payload}"
                elif evt_type == "incoming_call":
                    incoming_call_prompt = f"Incoming call from {payload}! Accept (y/n)?"
                    status = incoming_call_prompt
                    call_partner = payload
                elif evt_type == "update":
                    # Message received or sent, redraw messages
                    pass
                elif evt_type == "update_status":
                    # User status updated, redraw chats and possibly messages
                    pass
                elif evt_type == "ready":
                    status = "Ready"

        except queue.Empty:
            pass # No events in queue, continue with UI redraw

        draw_chats(win_chats, current_chat)
        draw_msgs(win_msgs, current_chat)
        draw_input(win_input, input_buf, status)

        # Handle incoming call prompt interaction
        if incoming_call_prompt:
            ch = -1
            try:
                ch = win_input.get_wch()
            except curses.error:
                pass # No key pressed

            if ch == "y" or ch == "Y":
                _sock = _get_voip_socket()
                udp_port = _sock.getsockname()[1] # Get the bound port
                io.emit("accept_call", {"to": call_partner, "udp_port": udp_port, "client_ip": _local_ip()})
                incoming_call_prompt = None
                status = "Call accepted!"
                in_call = True
            elif ch == "n" or ch == "N":
                io.emit("reject_call", {"to": call_partner})
                incoming_call_prompt = None
                status = "Call rejected."
                call_partner = None
            time.sleep(0.05)
            continue

        # Normal input handling
        ch = -1
        try:
            ch = win_input.get_wch()
        except curses.error:
            time.sleep(0.05)
            continue

        if ch in ("\x03", "\x04"): # Ctrl+C or Ctrl+D to exit
            break
        if ch == "\x0b": # Ctrl+K for previous chat
            if chats:
                idx = chats.index(current_chat) if current_chat in chats else 0
                current_chat = chats[(idx-1) % len(chats)]
            continue
        if ch == "\x0c": # Ctrl+L for next chat
            if chats:
                idx = chats.index(current_chat) if current_chat in chats else -1
                current_chat = chats[(idx+1) % len(chats)]
            continue
        if ch == "\x15": # Ctrl+U to update statuses
            _request_all_known_user_statuses()
            event_q.put(("info", f"Requested statuses for all users."))
            continue
        if ch == "\x0e": # Ctrl+N for new chat
            curses.curs_set(1); curses.echo(); win_input.nodelay(False)
            win_input.addstr(1,1,"Phone: "); win_input.clrtoeol()
            try:
                newp = win_input.getstr().decode().strip()
            except Exception: # Handle potential errors if user just presses enter
                newp = ""
            curses.noecho(); win_input.nodelay(True); curses.curs_set(1)
            if newp: _ensure_chat(newp); current_chat = newp
            input_buf=""; continue

        if ch == "\x06": # Ctrl+F for send file
            curses.curs_set(1); curses.echo(); win_input.nodelay(False)
            win_input.addstr(1,1,"Path: "); win_input.clrtoeol()
            try:
                path = win_input.getstr().decode().strip()
            except Exception:
                path = ""
            curses.noecho(); win_input.nodelay(True); curses.curs_set(1)
            if current_chat and os.path.isfile(path):
                _send_file(path, current_chat)
            else: status = "Invalid file path or no chat selected."
            input_buf=""; continue

        if ch == "\x0f": # Ctrl+O for call actions
            if current_chat:
                if not in_call:
                    _start_call(current_chat)
                    status = f"Calling {current_chat}..."
                else: # If already in a call, assume this is to end it
                    if call_partner == current_chat: # Only end if it's the current active call
                        io.emit("end_call", {"to": current_chat, "reason": "ended by user"})
                        in_call = False
                        call_partner = None
                        _end_voip_session()
                        status = "Call ended."
                    else:
                        status = f"Already in a call with {call_partner}. End that first."
            else:
                status = "No chat selected to call."
            input_buf = ""
            continue

        if isinstance(ch,str) and ch.isprintable(): input_buf += ch; continue
        if ch in (curses.KEY_BACKSPACE,"\x7f"): input_buf = input_buf[:-1]; continue
        if ch == "\n":
            if current_chat and input_buf.strip():
                if in_call:
                    if input_buf.strip().lower() == "end":
                        io.emit("end_call", {"to": current_chat, "reason": "ended by user"})
                        in_call = False
                        call_partner = None
                        _end_voip_session()
                        status = "Call ended."
                    else:
                        status = "In call. Type 'end' to hang up or wait for call to end."
                else:
                    _send_text(input_buf.strip(), current_chat)
            else:
                status = "No chat selected or empty message."
            input_buf=""; continue

    io.disconnect()

# ===== Sending helpers =====

def _request_all_known_user_statuses():
    # Only request for users in current chats
    users_to_check = [c for c in chats if c != PHONE]
    if not users_to_check:
        event_q.put(("info", "No other users in your chat list to check status for."))
        return
    io.emit("check_status", {"from": PHONE, "users": users_to_check})

def _send_text(text, to):
    ts_iso = datetime.now().isoformat()
    ts_disp = datetime.now().strftime("%H:%M")
    encrypted = fernet.encrypt(text.encode()).decode()
    io.emit("send_text", {"from": PHONE,"to": to,"text": encrypted,"ts": ts_iso})
    with lock:
        message_queues[to].append(("→", text, ts_disp)); _trim(to)
    event_q.put(("update", None)) # Notify UI to redraw

def _send_file(path, to):
    _request_all_known_user_statuses()

    if user_online_status.get(to) == "Online":
        mime,_ = mimetypes.guess_type(path)
        try:
            with open(path,"rb") as f:
                b64 = base64.b64encode(f.read()).decode()
        except FileNotFoundError:
            event_q.put(("error", f"File not found: {path}"))
            return
        except Exception as e:
            event_q.put(("error", f"Could not read file: {e}"))
            return

        ts = datetime.now().isoformat()
        msg = f"[File] Sending {os.path.basename(path)} to {to}..."
        msg = fernet.encrypt(msg.encode()).decode()

        io.emit("send_file", {
            "from": PHONE,
            "to": to,
            "msg": msg,
            "filename": os.path.basename(path),
            "mimetype": mime or "application/octet-stream", # Default if mimetype is unknown
            "b64_string": b64,
            "ts": ts
        })
        with lock:
            message_queues[to].append(("→", msg, _fmt_ts(ts))); _trim(to)
        event_q.put(("info", f"Sent file {os.path.basename(path)} to {to}."))
        event_q.put(("update", None)) # Notify UI to redraw
    else:
        event_q.put(("error", f"User {to} is offline. File cannot be sent."))
        return

def _start_call(to_phone):
    _request_all_known_user_statuses()

    if user_online_status.get(to_phone) == "Online":
        global _voip_sock
        _sock = _get_voip_socket()
        udp_port = _sock.getsockname()[1]

        msg = f"[Call] Calling {to_phone}..."
        msg = fernet.encrypt(msg.encode()).decode()
        ts = datetime.now().isoformat()

        io.emit("start_call", {"from": PHONE, "to": to_phone, "msg": msg, "udp_port": udp_port, "client_ip": _local_ip()})
        with lock:
            message_queues[to_phone].append(("→", msg, _fmt_ts(ts))); _trim(to_phone)
        event_q.put(("update", None)) # Notify UI to redraw
    else:
        event_q.put(("error", f"User {to_phone} is offline. Cannot start call."))
        return

# ===== Entry =====
if __name__ == "__main__":
    try:
        io.connect(SERVER, transports=["websocket"])
        threading.Thread(target=io.wait, daemon=True).start()
        curses.wrapper(ui_loop)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)