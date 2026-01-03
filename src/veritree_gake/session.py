import hmac
import hashlib

class GroupSession:
    def __init__(self, group_key: bytes, sid: bytes):
        self.group_key = group_key
        self.sid = sid
        self.nonce_counter = 0
    
    def encrypt_message(self, plaintext: bytes, sender_id: str) -> bytes:
        """AEAD-like message encryption with sender auth."""
        nonce = self.nonce_counter.to_bytes(12, 'big')
        self.nonce_counter += 1
        
        # Simplified: HMAC(key, nonce || sender || plaintext)
        msg = nonce + sender_id.encode() + plaintext
        tag = hmac.new(self.group_key, msg, hashlib.sha256).digest()[:16]
        return nonce + tag + plaintext
    
    def decrypt_message(self, ciphertext: bytes, sender_id: str) -> bytes:
        """Decrypt + verify."""
        if len(ciphertext) < 28:
            raise ValueError("Invalid ciphertext")
        nonce, tag, payload = ciphertext[:12], ciphertext[12:28], ciphertext[28:]
        
        expected_tag = hmac.new(
            self.group_key,
            nonce + sender_id.encode() + payload,
            hashlib.sha256
        ).digest()[:16]
        
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Auth failed")
        return payload
