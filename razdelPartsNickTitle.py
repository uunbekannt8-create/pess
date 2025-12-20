import socket
import threading
import struct
import os
from datetime import datetime

REMOTE_IP = '87.98.152.71'
GAME_PORT = 7777
LOCAL_PORT = 18888

class GameCrypt:
    """Реализация L2J GameCrypt по исходникам"""
   
    def __init__(self, key_bytes):
        self._inKey = bytearray(16)
        self._outKey = bytearray(16)
        self._isEnabled = False
        self.decrypt_count = 0
       
        for i in range(min(len(key_bytes), 16)):
            self._inKey[i] = key_bytes[i]
            self._outKey[i] = key_bytes[i]
   
    def decrypt(self, data):
        if len(data) < 3:
            return data
       
        raw = bytearray(data)
        offset = 2
        size = len(data) - offset
       
        if not self._isEnabled:
            self._isEnabled = True
            return bytes(raw)
       
        temp = 0
        for i in range(size):
            temp2 = raw[offset + i] & 0xFF
            new_byte = (temp2 ^ self._inKey[i & 15] ^ temp) & 0xFF
            raw[offset + i] = new_byte
            temp = temp2  # Ревертим к оригиналу L2J: используем raw byte для цепочки
       
        old = (self._inKey[8] & 0xFF)
        old |= ((self._inKey[9] << 8) & 0xFF00)
        old |= ((self._inKey[10] << 16) & 0xFF0000)
        old |= ((self._inKey[11] << 24) & 0xFF000000)
       
        old = (old + size) & 0xFFFFFFFF
       
        self._inKey[8] = old & 0xFF
        self._inKey[9] = (old >> 8) & 0xFF
        self._inKey[10] = (old >> 16) & 0xFF
        self._inKey[11] = (old >> 24) & 0xFF
       
        self.decrypt_count += 1
        return bytes(raw)

session_crypts = {}
session_lock = threading.Lock()

def log_message(message, to_console=True, to_file=True):
    print(message)

def format_hex_dump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:04X} {hex_part:<{width*3}} {ascii_part}")
    return '\n'.join(lines)

def save_hex_dump(direction, packet_id, raw_data, decrypted_data):
    print(f"\n{'='*80}")
    print(f"HEX DUMP: {direction} Packet 0x{packet_id:02X}")
    print(f"{'='*80}")
    print("DECRYPTED:")
    print(format_hex_dump(decrypted_data[:200]))  # Первые 200 байт
    print(f"{'='*80}\n")

def read_string_utf16_at_offset(data, offset):
    """Читает UTF-16LE строку, позволяя пропуск до 2 невалидных символов подряд"""
    chars = []
    i = offset
    max_length = 50
    invalid_count = 0
   
    while i < len(data) - 1 and len(chars) < max_length and invalid_count < 3:
        b1, b2 = data[i], data[i + 1]
       
        if b1 == 0 and b2 == 0:
            break
       
        char_code = b1 | (b2 << 8)
       
        if (32 <= char_code <= 126 or
            0x0100 <= char_code <= 0x024F or
            0x0400 <= char_code <= 0x04FF):
            chars.append(chr(char_code))
            invalid_count = 0
        else:
            invalid_count += 1
            # Пропускаем, не добавляем
       
        i += 2
   
    return ''.join(chars)

def find_all_possible_names(data):
    found_names = []
    seen = set()
   
    for offset in range(3, len(data) - 20, 2):  # Шаг 2 для UTF-16
        name = read_string_utf16_at_offset(data, offset)
       
        if len(name) >= 3 and name not in seen:
            seen.add(name)
            found_names.append({
                'string': name,
                'offset': offset,
                'length': len(name)
            })
   
    found_names.sort(key=lambda x: x['length'], reverse=True)
   
    return found_names

def parse_userinfo(data):
    try:
        if len(data) < 30:
            return None
       
        all_names = find_all_possible_names(data)
        if not all_names:
            return None
       
        name = all_names[0]['string']
        title = all_names[1]['string'] if len(all_names) > 1 and len(all_names[1]['string']) >= 3 else ''
       
        object_id = 0
        for i in range(3, min(50, len(data) - 4), 4):
            val = struct.unpack('<I', data[i:i+4])[0]
            if 200000 < val < 300000000:
                object_id = val
                break
       
        return {
            'name': name,
            'title': title,
            'object_id': object_id
        }
    except:
        return None

def parse_charinfo(data):
    try:
        if len(data) < 30:
            return None
       
        all_names = find_all_possible_names(data)
        if not all_names:
            return None
       
        name = all_names[0]['string']
        title = all_names[1]['string'] if len(all_names) > 1 and len(all_names[1]['string']) >= 3 else ''
       
        object_id = 0
        for i in range(3, min(50, len(data) - 4), 4):
            val = struct.unpack('<I', data[i:i+4])[0]
            if 200000 < val < 300000000:
                object_id = val
                break
       
        return {
            'name': name,
            'title': title,
            'object_id': object_id
        }
    except:
        return None

def bridge(src, dst, direction, is_server, session_id):
    try:
        data = src.recv(65536)
       
        if not is_server and data.startswith(b'\x04'):
            src.sendall(b'\x00\x5A\x00\x00\x00\x00\x00\x00')
            data = src.recv(65536)
       
        while data:
            if is_server and len(data) >= 12 and data[2] == 0x2e:
                raw_key = data[4:12]
                log_message(f"\n{'🔑'*40}")
                log_message(f"[INIT PACKET] Key (8 bytes): {raw_key.hex().upper()}")
                log_message(f"Full packet: {data[:20].hex()}")
                log_message(f"{'🔑'*40}\n")
               
                with session_lock:
                    session_crypts[session_id] = {
                        'S->C': GameCrypt(raw_key),
                        'C->S': GameCrypt(raw_key)
                    }
               
                dst.sendall(data)
                data = src.recv(65536)
                continue
           
            dec = data
            was_encrypted = False
           
            if session_id in session_crypts and direction in session_crypts[session_id]:
                with session_lock:
                    dec = session_crypts[session_id][direction].decrypt(data)
                    was_encrypted = True
           
            p_id = dec[2] if len(dec) > 2 else 0
           
            show_hex_for = [0x31, 0x32]
           
            if p_id in show_hex_for:
                save_hex_dump(direction, p_id, data, dec)
           
            parsed = None
            if p_id == 0x31:
                parsed = parse_charinfo(dec)
                if parsed:
                    print(f"\n{'='*60}")
                    print(f"👤 ПЕРСОНАЖ РЯДОМ")
                    print(f"{'='*60}")
                    print(f"Name: {parsed['name']}")
                    print(f"Title: {parsed['title']}")
                    print(f"Object ID: {parsed['object_id']}")
                    print(f"{'='*60}\n")
           
            elif p_id == 0x32:
                parsed = parse_userinfo(dec)
                if parsed:
                    print(f"\n{'='*60}")
                    print(f"⚔️ ВАШ ПЕРСОНАЖ")
                    print(f"{'='*60}")
                    print(f"Name: {parsed['name']}")
                    print(f"Title: {parsed['title']}")
                    print(f"Object ID: {parsed['object_id']}")
                    print(f"{'='*60}\n")
           
            dst.sendall(data)
            data = src.recv(65536)
   
    except Exception as e:
        log_message(f"\n[!] Error: {e}")
        import traceback
        log_message(traceback.format_exc())
   
    finally:
        with session_lock:
            if session_id in session_crypts:
                del session_crypts[session_id]
        try:
            src.close()
            dst.close()
        except:
            pass

def start():
    print("[*] Proxy: 127.0.0.1:{LOCAL_PORT} -> {REMOTE_IP}:{GAME_PORT}")
    print("[*] Reverted decryption chain to standard L2J (temp = raw byte)")
    print("[*] String finder allows skipping up to 2 invalid chars")
    print("[*] Waiting...")
   
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', LOCAL_PORT))
    s.listen(5)
   
    session_counter = 0
   
    while True:
        try:
            c_sock, addr = s.accept()
            session_counter += 1
            log_message(f"\n[+] Connection #{session_counter}")
           
            r_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r_sock.connect((REMOTE_IP, GAME_PORT))
           
            threading.Thread(target=bridge, args=(c_sock, r_sock, "C->S", False, session_counter), daemon=True).start()
            threading.Thread(target=bridge, args=(r_sock, c_sock, "S->C", True, session_counter), daemon=True).start()
        except Exception as e:
            log_message(f"[!] Error: {e}")

if __name__ == "__main__":
    try:
        start()
    except Exception as e:
        print(f"\n[!] CRITICAL: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter...")