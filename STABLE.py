import socket
import threading
import struct

REMOTE_IP = '87.98.152.71'
GAME_PORT = 7777
LOCAL_PORT = 18888

class GameCrypt:
    """Стандартный L2J GameCrypt"""
   
    def __init__(self, key_bytes):
        self._inKey = bytearray(16)
        self._outKey = bytearray(16)
        self._isEnabled = False
       
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
            temp = temp2
       
        old = (self._inKey[8] & 0xFF)
        old |= ((self._inKey[9] << 8) & 0xFF00)
        old |= ((self._inKey[10] << 16) & 0xFF0000)
        old |= ((self._inKey[11] << 24) & 0xFF000000)
       
        old = (old + size) & 0xFFFFFFFF
       
        self._inKey[8] = old & 0xFF
        self._inKey[9] = (old >> 8) & 0xFF
        self._inKey[10] = (old >> 16) & 0xFF
        self._inKey[11] = (old >> 24) & 0xFF
       
        return bytes(raw)

def find_xor_key(data):
    """
    Находит динамический XOR ключ integrity.dll
    Ключ 16 байт, но последние 9 байт константны
    """
    # Ищем самый частый байт на каждой позиции (mod 16)
    from collections import Counter
    
    key = bytearray(16)
    
    for pos in range(16):
        bytes_at_pos = [data[i] for i in range(pos, len(data), 16)]
        most_common = Counter(bytes_at_pos).most_common(1)
        if most_common:
            key[pos] = most_common[0][0]
    
    return bytes(key)

def decrypt_integrity(data):
    """
    Расшифровывает данные после GameCrypt используя integrity.dll ключ
    """
    # Находим ключ
    xor_key = find_xor_key(data)
    
    # Расшифровываем
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ xor_key[i % 16]
    
    return bytes(result)

def read_utf16_string(data, offset):
    """Читает UTF-16LE строку"""
    chars = []
    i = offset
    
    while i < len(data) - 1:
        b1, b2 = data[i], data[i + 1]
        
        if b1 == 0 and b2 == 0:
            break
        
        char_code = b1 | (b2 << 8)
        
        try:
            chars.append(chr(char_code))
        except:
            break
        
        i += 2
    
    return ''.join(chars), i + 2

def parse_charinfo(data):
    """Парсит CharInfo (0x31)"""
    try:
        if len(data) < 30:
            return None
        
        offset = 0
        
        # Координаты X, Y, Z
        x = struct.unpack('<i', data[offset:offset+4])[0]
        y = struct.unpack('<i', data[offset+4:offset+8])[0]
        z = struct.unpack('<i', data[offset+8:offset+12])[0]
        offset += 12
        
        # Heading/Boat
        offset += 4
        
        # Object ID
        obj_id = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Name
        name, offset = read_utf16_string(data, offset)
        
        # Race, Sex, ClassId
        if offset + 12 <= len(data):
            race = struct.unpack('<I', data[offset:offset+4])[0]
            sex = struct.unpack('<I', data[offset+4:offset+8])[0]
            class_id = struct.unpack('<I', data[offset+8:offset+12])[0]
            offset += 12
            
            # Пропускаем Item IDs (22 * 4 = 88 байт)
            offset += 88
            
            # Пропускаем Augmentation данные (много writeH)
            # Примерно +200 байт до title
            offset += 200
            
            # Title
            if offset < len(data):
                title, _ = read_utf16_string(data, offset)
            else:
                title = ""
            
            races = ['Human', 'Elf', 'Dark Elf', 'Orc', 'Dwarf', 'Kamael']
            race_name = races[race] if race < len(races) else f"Race{race}"
            
            return {
                'name': name,
                'title': title,
                'object_id': obj_id,
                'x': x, 'y': y, 'z': z,
                'race': race_name,
                'sex': 'Female' if sex == 1 else 'Male',
                'class_id': class_id
            }
        
        return {'name': name, 'object_id': obj_id, 'x': x, 'y': y, 'z': z}
        
    except Exception as e:
        print(f"[!] Parse CharInfo error: {e}")
        return None

def parse_userinfo(data):
    """Парсит UserInfo (0x32)"""
    try:
        if len(data) < 30:
            return None
        
        offset = 0
        
        # Координаты
        x = struct.unpack('<i', data[offset:offset+4])[0]
        y = struct.unpack('<i', data[offset+4:offset+8])[0]
        z = struct.unpack('<i', data[offset+8:offset+12])[0]
        offset += 12
        
        # Heading
        heading = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Object ID
        obj_id = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Name
        name, offset = read_utf16_string(data, offset)
        
        # Race, Sex, ClassId
        race = struct.unpack('<I', data[offset:offset+4])[0]
        sex = struct.unpack('<I', data[offset+4:offset+8])[0]
        class_id = struct.unpack('<I', data[offset+8:offset+12])[0]
        offset += 12
        
        # Level
        level = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Exp
        exp = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        # Stats
        stats = {}
        stats['str'] = struct.unpack('<I', data[offset:offset+4])[0]
        stats['dex'] = struct.unpack('<I', data[offset+4:offset+8])[0]
        stats['con'] = struct.unpack('<I', data[offset+8:offset+12])[0]
        stats['int'] = struct.unpack('<I', data[offset+12:offset+16])[0]
        stats['wit'] = struct.unpack('<I', data[offset+16:offset+20])[0]
        stats['men'] = struct.unpack('<I', data[offset+20:offset+24])[0]
        offset += 24
        
        # HP/MP
        max_hp = struct.unpack('<I', data[offset:offset+4])[0]
        cur_hp = struct.unpack('<I', data[offset+4:offset+8])[0]
        max_mp = struct.unpack('<I', data[offset+8:offset+12])[0]
        cur_mp = struct.unpack('<I', data[offset+12:offset+16])[0]
        offset += 16
        
        # SP
        sp = struct.unpack('<I', data[offset:offset+4])[0]
        
        races = ['Human', 'Elf', 'Dark Elf', 'Orc', 'Dwarf', 'Kamael']
        race_name = races[race] if race < len(races) else f"Race{race}"
        
        return {
            'name': name,
            'object_id': obj_id,
            'x': x, 'y': y, 'z': z,
            'race': race_name,
            'sex': 'Female' if sex == 1 else 'Male',
            'class_id': class_id,
            'level': level,
            'exp': exp,
            'stats': stats,
            'hp': f"{cur_hp}/{max_hp}",
            'mp': f"{cur_mp}/{max_mp}",
            'sp': sp
        }
        
    except Exception as e:
        print(f"[!] Parse UserInfo error: {e}")
        return None

session_crypts = {}
session_lock = threading.Lock()

def bridge(src, dst, direction, is_server, session_id):
    try:
        data = src.recv(65536)
       
        if not is_server and data.startswith(b'\x04'):
            src.sendall(b'\x00\x5A\x00\x00\x00\x00\x00\x00')
            data = src.recv(65536)
       
        while data:
            # Init packet
            if is_server and len(data) >= 12 and data[2] == 0x2e:
                raw_key = data[4:12]
                print(f"\n{'='*80}")
                print(f"🔑 Blowfish Key: {raw_key.hex().upper()}")
                print(f"{'='*80}\n")
               
                with session_lock:
                    session_crypts[session_id] = {
                        'S->C': GameCrypt(raw_key),
                        'C->S': GameCrypt(raw_key)
                    }
               
                dst.sendall(data)
                data = src.recv(65536)
                continue
           
            # Расшифровка GameCrypt
            dec = data
            if session_id in session_crypts and direction in session_crypts[session_id]:
                with session_lock:
                    dec = session_crypts[session_id][direction].decrypt(data)
           
            p_id = dec[2] if len(dec) > 2 else 0
           
            # Расшифровка integrity.dll
            if p_id in [0x31, 0x32] and len(dec) > 20:
                # Дополнительная расшифровка
                integrity_dec = decrypt_integrity(dec[3:])
                
                if p_id == 0x31:  # CharInfo
                    parsed = parse_charinfo(integrity_dec)
                    if parsed:
                        print(f"\n{'='*60}")
                        print(f"👤 ПЕРСОНАЖ РЯДОМ")
                        print(f"{'='*60}")
                        print(f"Имя:       {parsed['name']}")
                        print(f"Титул:     {parsed.get('title', '')}")
                        print(f"Object ID: {parsed['object_id']}")
                        print(f"Координаты: X={parsed['x']}, Y={parsed['y']}, Z={parsed['z']}")
                        if 'race' in parsed:
                            print(f"Раса:      {parsed['race']}")
                            print(f"Пол:       {parsed['sex']}")
                            print(f"Class ID:  {parsed['class_id']}")
                        print(f"{'='*60}\n")
                
                elif p_id == 0x32:  # UserInfo
                    parsed = parse_userinfo(integrity_dec)
                    if parsed:
                        print(f"\n{'='*60}")
                        print(f"⚔️  ВАШ ПЕРСОНАЖ")
                        print(f"{'='*60}")
                        print(f"Имя:       {parsed['name']}")
                        print(f"Object ID: {parsed['object_id']}")
                        print(f"Уровень:   {parsed['level']}")
                        print(f"Раса:      {parsed['race']}")
                        print(f"Пол:       {parsed['sex']}")
                        print(f"Class ID:  {parsed['class_id']}")
                        print(f"STR/DEX/CON: {parsed['stats']['str']}/{parsed['stats']['dex']}/{parsed['stats']['con']}")
                        print(f"INT/WIT/MEN: {parsed['stats']['int']}/{parsed['stats']['wit']}/{parsed['stats']['men']}")
                        print(f"HP:        {parsed['hp']}")
                        print(f"MP:        {parsed['mp']}")
                        print(f"SP:        {parsed['sp']}")
                        print(f"{'='*60}\n")
           
            dst.sendall(data)
            data = src.recv(65536)
   
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
   
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
    print(f"{'='*80}")
    print(f"  L2 KAMAEL PACKET PARSER - FULL DECRYPTION")
    print(f"  GameCrypt + integrity.dll взломаны!")
    print(f"{'='*80}\n")
    print(f"[*] Proxy: 127.0.0.1:{LOCAL_PORT} -> {REMOTE_IP}:{GAME_PORT}")
    print(f"[*] Читаем: ники, титулы, статы, координаты")
    print(f"[*] Ожидание подключения...\n")
   
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', LOCAL_PORT))
    s.listen(5)
   
    session_counter = 0
   
    while True:
        try:
            c_sock, addr = s.accept()
            session_counter += 1
            print(f"[+] Подключение #{session_counter}\n")
           
            r_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r_sock.connect((REMOTE_IP, GAME_PORT))
           
            threading.Thread(target=bridge, args=(c_sock, r_sock, "C->S", False, session_counter), daemon=True).start()
            threading.Thread(target=bridge, args=(r_sock, c_sock, "S->C", True, session_counter), daemon=True).start()
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    try:
        start()
    except KeyboardInterrupt:
        print("\n[*] Остановлено")
    except Exception as e:
        print(f"\n[!] CRITICAL: {e}")
        import traceback
        traceback.print_exc()