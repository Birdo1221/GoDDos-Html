import socket
import threading
import time

class BotClient:
    def __init__(self, server_ip='127.0.0.1', server_port=9080):
        self.server_ip = server_ip
        self.server_port = server_port
        self.running = False
        self.socket = None

    def connect(self):
        """Connect to the bot server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            self.running = True
            print(f"[+] Connected to {self.server_ip}:{self.server_port}")
            
            # Start listening thread
            threading.Thread(target=self.listen_for_commands, daemon=True).start()
            
            # Send initial handshake
            self.socket.sendall(b"Bot connected\n")
            
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")

    def listen_for_commands(self):
        """Listen for incoming commands from server"""
        while self.running:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                    
                command = data.decode().strip()
                print(f"\n[+] Received command: {command}")
                
                # Simulate processing
                print("[*] Processing command...")
                time.sleep(1)
                
                # Send response back
                response = f"Executed: {command}\n"
                self.socket.sendall(response.encode())
                
            except Exception as e:
                print(f"[-] Error receiving command: {str(e)}")
                self.running = False
                break

    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[+] Disconnected from server")

if __name__ == "__main__":
    print("""\
  ____        _   
 |  _ \      | |  
 | |_) | ___ | |_ 
 |  _ < / _ \| __|
 | |_) | (_) | |_ 
 |____/ \___/ \__|
 Simple Bot Client
""")
    
    bot = BotClient()
    bot.connect()
    
    try:
        while bot.running:
            time.sleep(1)
    except KeyboardInterrupt:
        bot.disconnect()