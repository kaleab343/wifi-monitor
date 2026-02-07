"""
Low-level network client for router communication
Handles raw socket connections and HTTP requests
"""

import socket
import json as json_lib
from typing import Tuple, Optional, Dict


class NetworkClient:
    """Handles low-level HTTP communication with router"""
    
    def __init__(self, router_ip: str, timeout: int = 10):
        self.router_ip = router_ip
        self.timeout = timeout
    
    def raw_get_request(self, endpoint: str, extra_headers: Optional[Dict] = None) -> Tuple[bool, any]:
        """Make GET request using raw socket"""
        # Build headers
        headers = {
            'Host': self.router_ip,
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'close'
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        # Build HTTP request
        request = f"GET {endpoint} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        
        # Send via socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.router_ip, 80))
            sock.sendall(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            text = response.decode('utf-8', errors='ignore')
            
            # Router sends JSON without HTTP headers, just raw JSON
            json_start = text.find('{')
            if json_start >= 0:
                json_text = text[json_start:]
                try:
                    data = json_lib.loads(json_text)
                    return True, data
                except:
                    return True, json_text
            
            return False, "No JSON in response"
            
        except socket.timeout:
            return False, "Request timeout"
        except Exception as e:
            return False, f"Socket error: {e}"
        finally:
            sock.close()
    
    def raw_post_request(self, endpoint: str, data: dict, extra_headers: Optional[Dict] = None) -> Tuple[bool, any]:
        """Make POST request using raw socket"""
        # Build JSON payload
        payload = json_lib.dumps(data)
        
        # Build headers
        headers = {
            'Host': self.router_ip,
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Content-Type': 'json',
            'Content-Length': str(len(payload)),
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'close'
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        # Build HTTP request
        request = f"POST {endpoint} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        request += payload
        
        # Send via socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.router_ip, 80))
            sock.sendall(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            text = response.decode('utf-8', errors='ignore')
            
            # Look for JSON in response
            json_start = text.find('{')
            if json_start >= 0:
                json_text = text[json_start:]
                try:
                    result = json_lib.loads(json_text)
                    return True, result
                except:
                    return True, json_text
            
            # No JSON, but request succeeded
            return True, text
            
        except socket.timeout:
            return False, "Request timeout"
        except Exception as e:
            return False, f"Socket error: {e}"
        finally:
            sock.close()
