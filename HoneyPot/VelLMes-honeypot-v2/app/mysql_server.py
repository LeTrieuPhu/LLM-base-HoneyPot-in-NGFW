import socket
import threading
import logging
import requests
import yaml
import os
from datetime import datetime
import time

class GroqClient:
    def __init__(self, api_key, model="llama3-70b-8192"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        
    def generate_response(self, prompt, max_tokens=1200, temperature=0.2):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content'].strip()
            else:
                return "ERROR 1064 (42000): You have an error in your SQL syntax"
        except Exception as e:
            return "ERROR 2003 (HY000): Can't connect to MySQL server"

class SimpleMySQLHoneypot:
    def __init__(self, config_file='/app/configs/configMySQL.yml'):
        self.load_config(config_file)
        self.setup_logging()
        self.groq = GroqClient(
            api_key=os.getenv('GROQ_API_KEY'),
            model=os.getenv('MODEL', 'llama3-70b-8192')
        )
        self.stats = {'connections': 0, 'queries': 0}
        
    def load_config(self, config_file):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
    def setup_logging(self):
        log_file = self.config['logging']['log_file']
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        self.logger = logging.getLogger('MySQL-Honeypot')
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
    def log_conversation(self, session_id, data):
        """Log conversation to file"""
        conv_file = self.config['logging']['conversation_file']
        os.makedirs(os.path.dirname(conv_file), exist_ok=True)
        
        with open(conv_file, 'a') as f:
            f.write(f"[{datetime.now()}] Session {session_id}: {data}\n")
            
    def handle_connection(self, client_socket, addr):
        session_id = f"{addr[0]}_{int(time.time())}"
        self.stats['connections'] += 1
        
        self.logger.info(f"MySQL connection from {addr[0]}:{addr[1]} - Session: {session_id}")
        self.log_conversation(session_id, f"Connection established from {addr[0]}")
        
        try:
            # Send simple text-based MySQL prompt
            welcome = """MySQL Honeypot Server 8.0.32-Ubuntu
Type 'help;' or '\\h' for help. Type '\\c' to clear buffer.

mysql> """
            client_socket.send(welcome.encode())
            
            # Query loop
            while True:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Try to decode as text query
                    query = data.decode('utf-8', errors='ignore').strip()
                    
                    # Skip binary handshake data
                    if len(query) < 2 or '\x00' in query[:10]:
                        # This looks like binary MySQL protocol, send fake OK
                        client_socket.send(b"OK\nmysql> ")
                        continue
                    
                    if not query:
                        continue
                        
                    if query.lower() in ['quit', 'exit', '\\q']:
                        client_socket.send(b"Bye\n")
                        break
                        
                    self.stats['queries'] += 1
                    self.logger.info(f"MySQL query from {addr[0]} [{session_id}]: {query}")
                    self.log_conversation(session_id, f"Query: {query}")
                    
                    # Generate AI response
                    full_prompt = f"""{self.config['personality_prompt']}

SQL Query: {query}

Provide realistic MySQL response output:"""
                    
                    response = self.groq.generate_response(
                        full_prompt,
                        max_tokens=self.config['llm']['max_tokens'],
                        temperature=self.config['llm']['temperature']
                    )
                    
                    # Send response with prompt
                    full_response = f"{response}\n\nmysql> "
                    client_socket.send(full_response.encode())
                    self.log_conversation(session_id, f"Response: {response}")
                    
                except socket.timeout:
                    self.logger.info(f"MySQL session timeout - {session_id}")
                    break
                except Exception as e:
                    self.logger.error(f"MySQL query error: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"MySQL connection error: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"MySQL session ended - {session_id}")
            
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.config['server']['host'], self.config['server']['port']))
        server.listen(self.config['server']['max_connections'])
        
        self.logger.info(f"MySQL Honeypot listening on {self.config['server']['host']}:{self.config['server']['port']}")
        
        while True:
            try:
                client, addr = server.accept()
                client.settimeout(self.config['server']['timeout'])
                
                thread = threading.Thread(target=self.handle_connection, args=(client, addr))
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                self.logger.error(f"MySQL server error: {e}")

if __name__ == "__main__":
    honeypot = SimpleMySQLHoneypot()
    honeypot.start()