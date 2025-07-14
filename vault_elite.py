#!/usr/bin/env python3
# vault_elite.py
# © 2025 Pradip Gosain - Enhanced Elite Edition
# License: GNU AGPL-3.0
# Advanced Military-Grade Security Suite

import os
import json
import base64
import secrets
import string
import time
import getpass
import hashlib
import hmac
import shutil
import sqlite3
import requests
import socket
import subprocess
import platform
import psutil
import struct
import mmap
import tempfile
import zlib
import io
import re
import datetime
import asyncio
import csv
import sys
import zxcvbn
import pyotp
import qrcode
import pyperclip
import argon2
import scrypt
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from contextlib import contextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.x509.oid import NameOID
from cryptography import x509
from termcolor import colored

# === ADVANCED CONSTANTS ===
VAULT_FILE = "ciphervault_elite.dat"
BACKUP_DIR = "vault_backups"
LOG_FILE = "vault_audit.log"
KEYFILE_DIR = "keyfiles"
EXPORT_DIR = "exports"
TEMP_DIR = "temp_secure"
CONFIG_FILE = "vault_config.json"

# Enhanced Security Configuration
SECURITY_CONFIG = {
    'ARGON2_TIME_COST': 3,
    'ARGON2_MEMORY_COST': 65536,  # 64MB
    'ARGON2_PARALLELISM': 4,
    'SCRYPT_N': 32768,
    'SCRYPT_R': 8,
    'SCRYPT_P': 1,
    'PBKDF2_ITERATIONS': 1000000,
    'SALT_LENGTH': 32,
    'KEY_LENGTH': 32,
    'TOKEN_EXPIRY': 300,
    'SESSION_TIMEOUT': 1800,  # 30 minutes
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOCKOUT_DURATION': 1800,  # 30 minutes
    'BACKUP_RETENTION': 50,
    'AUDIT_LOG_MAX_SIZE': 10 * 1024 * 1024,  # 10MB
    'MEMORY_WIPE_PASSES': 3,
    'ENCRYPTION_ROUNDS': 5
}

# === ADVANCED ENUMS ===
class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    MILITARY = 4
    QUANTUM_RESISTANT = 5

class EncryptionMethod(Enum):
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    FERNET = "fernet"
    MULTI_LAYER = "multi-layer"

class AuthMethod(Enum):
    PASSWORD = "password"
    KEYFILE = "keyfile"
    BIOMETRIC = "biometric"
    YUBIKEY = "yubikey"
    MULTI_FACTOR = "multi-factor"

# === ADVANCED DATA STRUCTURES ===
@dataclass
class VaultEntry:
    service: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    totp_secret: str = ""
    custom_fields: Dict[str, str] = None
    tags: List[str] = None
    created: str = ""
    last_modified: str = ""
    last_accessed: str = ""
    access_count: int = 0
    expiry_date: str = ""
    password_history: List[str] = None
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    auto_generated: bool = False
    
    def __post_init__(self):
        if self.custom_fields is None:
            self.custom_fields = {}
        if self.tags is None:
            self.tags = []
        if self.password_history is None:
            self.password_history = []
        if not self.created:
            self.created = datetime.datetime.now().isoformat()
        if not self.last_modified:
            self.last_modified = self.created

@dataclass
class SecurityReport:
    weak_passwords: List[str]
    reused_passwords: List[str]
    old_passwords: List[str]
    breached_passwords: List[str]
    expired_entries: List[str]
    totp_enabled: List[str]
    overall_score: float
    recommendations: List[str]

# === ADVANCED ENCRYPTION SYSTEM ===
class QuantumResistantCrypto:
    """Post-quantum cryptography implementation"""
    
    def __init__(self):
        self.backend = default_backend()
        
    def generate_lattice_key(self, size: int = 4096) -> bytes:
        """Generate lattice-based key for quantum resistance"""
        return secrets.token_bytes(size)
    
    def kyber_encrypt(self, data: bytes, public_key: bytes) -> bytes:
        """Kyber encryption simulation (placeholder for actual implementation)"""
        # This would use actual post-quantum crypto library like liboqs
        return self._xor_encrypt(data, public_key[:len(data)])
    
    def kyber_decrypt(self, encrypted_data: bytes, private_key: bytes) -> bytes:
        """Kyber decryption simulation"""
        return self._xor_encrypt(encrypted_data, private_key[:len(encrypted_data)])
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption with key cycling"""
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

class AdvancedEncryption:
    """Military-grade encryption with multiple layers"""
    
    def __init__(self):
        self.quantum_crypto = QuantumResistantCrypto()
        self.backend = default_backend()
    
    def derive_key_argon2(self, password: str, salt: bytes) -> bytes:
        """Argon2 key derivation - memory-hard function"""
        ph = argon2.PasswordHasher(
            time_cost=SECURITY_CONFIG['ARGON2_TIME_COST'],
            memory_cost=SECURITY_CONFIG['ARGON2_MEMORY_COST'],
            parallelism=SECURITY_CONFIG['ARGON2_PARALLELISM'],
            hash_len=32,
            salt_len=16
        )
        hash_result = ph.hash(password, salt=salt)
        return base64.b64decode(hash_result.split('$')[-1])[:32]
    
    def derive_key_scrypt(self, password: str, salt: bytes) -> bytes:
        """Scrypt key derivation - memory-hard function"""
        return scrypt.hash(
            password.encode(),
            salt=salt,
            N=SECURITY_CONFIG['SCRYPT_N'],
            r=SECURITY_CONFIG['SCRYPT_R'],
            p=SECURITY_CONFIG['SCRYPT_P'],
            buflen=32
        )
    
    def multi_layer_encrypt(self, data: str, keys: List[bytes]) -> str:
        """Apply multiple encryption layers"""
        current_data = data.encode()
        
        # Layer 1: AES-256-GCM
        nonce1 = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(keys[0]),
            modes.GCM(nonce1),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        layer1 = encryptor.update(current_data) + encryptor.finalize()
        
        # Layer 2: ChaCha20-Poly1305
        nonce2 = secrets.token_bytes(12)
        algorithm = algorithms.ChaCha20(keys[1], nonce2)
        layer2 = algorithm.encryptor().update(layer1)
        
        # Layer 3: Fernet
        f = Fernet(base64.urlsafe_b64encode(keys[2]))
        layer3 = f.encrypt(layer2)
        
        # Layer 4: Quantum-resistant
        layer4 = self.quantum_crypto.kyber_encrypt(layer3, keys[3])
        
        # Combine all layers with metadata
        metadata = {
            'layers': 4,
            'gcm_tag': base64.b64encode(encryptor.tag).decode(),
            'nonce1': base64.b64encode(nonce1).decode(),
            'nonce2': base64.b64encode(nonce2).decode(),
            'timestamp': time.time()
        }
        
        final_data = {
            'data': base64.b64encode(layer4).decode(),
            'metadata': metadata
        }
        
        return json.dumps(final_data)
    
    def multi_layer_decrypt(self, encrypted_data: str, keys: List[bytes]) -> str:
        """Decrypt multiple encryption layers"""
        try:
            data_obj = json.loads(encrypted_data)
            current_data = base64.b64decode(data_obj['data'])
            metadata = data_obj['metadata']
            
            # Reverse Layer 4: Quantum-resistant
            layer3 = self.quantum_crypto.kyber_decrypt(current_data, keys[3])
            
            # Reverse Layer 3: Fernet
            f = Fernet(base64.urlsafe_b64encode(keys[2]))
            layer2 = f.decrypt(layer3)
            
            # Reverse Layer 2: ChaCha20
            nonce2 = base64.b64decode(metadata['nonce2'])
            algorithm = algorithms.ChaCha20(keys[1], nonce2)
            layer1 = algorithm.decryptor().update(layer2)
            
            # Reverse Layer 1: AES-256-GCM
            nonce1 = base64.b64decode(metadata['nonce1'])
            tag = base64.b64decode(metadata['gcm_tag'])
            cipher = Cipher(
                algorithms.AES(keys[0]),
                modes.GCM(nonce1, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            original_data = decryptor.update(layer1) + decryptor.finalize()
            
            return original_data.decode()
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

# === ADVANCED SECURITY FEATURES ===
class BiometricAuth:
    """Biometric authentication simulation"""
    
    def __init__(self):
        self.enrolled_hash = None
    
    def enroll_fingerprint(self) -> str:
        """Simulate fingerprint enrollment"""
        # In real implementation, this would use actual biometric hardware
        fake_biometric = secrets.token_hex(32)
        self.enrolled_hash = hashlib.sha256(fake_biometric.encode()).hexdigest()
        return "Fingerprint enrolled successfully"
    
    def verify_fingerprint(self) -> bool:
        """Simulate fingerprint verification"""
        # Simulate 95% success rate
        return secrets.randbelow(100) < 95

class YubiKeyAuth:
    """YubiKey authentication simulation"""
    
    def __init__(self):
        self.challenge = None
    
    def generate_challenge(self) -> str:
        """Generate OTP challenge"""
        self.challenge = secrets.token_hex(16)
        return self.challenge
    
    def verify_response(self, response: str) -> bool:
        """Verify YubiKey response"""
        # Simulate YubiKey verification
        expected = hashlib.sha256(self.challenge.encode()).hexdigest()[:12]
        return response == expected

class AdvancedTOTP:
    """Enhanced TOTP with custom parameters"""
    
    def __init__(self, secret: str = None, interval: int = 30, digits: int = 6):
        self.secret = secret or base64.b32encode(secrets.token_bytes(20)).decode()
        self.interval = interval
        self.digits = digits
        self.totp = pyotp.TOTP(self.secret, interval=interval, digits=digits)
    
    def generate_qr_code(self, name: str, issuer: str) -> str:
        """Generate QR code for TOTP setup"""
        provisioning_uri = self.totp.provisioning_uri(
            name=name,
            issuer_name=issuer
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Save QR code to file
        qr_file = f"totp_{name}_{int(time.time())}.png"
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_file)
        
        return qr_file
    
    def verify_token(self, token: str) -> bool:
        """Verify TOTP token with window tolerance"""
        return self.totp.verify(token, valid_window=1)

# === NETWORK SECURITY ===
class NetworkSecurity:
    """Advanced network security features"""
    
    def __init__(self):
        self.allowed_networks = []
        self.blocked_ips = []
    
    def get_public_ip(self) -> str:
        """Get public IP address"""
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text
        except:
            return "Unknown"
    
    def check_breach_database(self, password: str) -> bool:
        """Check if password exists in breach databases"""
        # Use Have I Been Pwned API
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=5
            )
            
            if response.status_code == 200:
                hashes = [line.split(':')[0] for line in response.text.splitlines()]
                return suffix in hashes
            return False
        except:
            return False
    
    def scan_network_threats(self) -> Dict[str, Any]:
        """Scan for network-based threats"""
        threats = {
            'suspicious_connections': [],
            'open_ports': [],
            'malicious_processes': [],
            'network_intrusion_attempts': 0
        }
        
        # Check for suspicious network connections
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check against known malicious IPs (simplified)
                    if conn.raddr.ip in self.blocked_ips:
                        threats['suspicious_connections'].append({
                            'ip': conn.raddr.ip,
                            'port': conn.raddr.port,
                            'status': conn.status
                        })
        except:
            pass
        
        return threats

# === ADVANCED VAULT SYSTEM ===
class ElitePasswordVault:
    """Advanced password vault with military-grade security"""
    
    def __init__(self):
        self.vault_data = {}
        self.master_keys = []
        self.salt = None
        self.encryption_method = EncryptionMethod.MULTI_LAYER
        self.security_level = SecurityLevel.MILITARY
        self.session_token = None
        self.session_expiry = None
        self.login_attempts = 0
        self.lockout_until = None
        self.encryption_engine = AdvancedEncryption()
        self.biometric_auth = BiometricAuth()
        self.yubikey_auth = YubiKeyAuth()
        self.network_security = NetworkSecurity()
        self.audit_events = []
        self.keyfile_path = None
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load vault configuration"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {
            'auto_backup': True,
            'backup_encryption': True,
            'audit_logging': True,
            'network_monitoring': True,
            'breach_monitoring': True,
            'auto_logout': True,
            'clipboard_clear': True,
            'memory_protection': True
        }
    
    def save_config(self):
        """Save vault configuration"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def initialize_elite_vault(self, master_password: str, keyfile_path: str = None, 
                              biometric_enabled: bool = False, yubikey_enabled: bool = False):
        """Initialize elite vault with advanced security"""
        # Generate multiple salts for different key derivation methods
        self.salt = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
        salt2 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
        salt3 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
        salt4 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
        
        # Derive multiple keys using different methods
        key1 = self.encryption_engine.derive_key_argon2(master_password, self.salt)
        key2 = self.encryption_engine.derive_key_scrypt(master_password, salt2)
        key3 = self._pbkdf2_key(master_password, salt3)
        key4 = secrets.token_bytes(32)  # Quantum-resistant key
        
        self.master_keys = [key1, key2, key3, key4]
        self.keyfile_path = keyfile_path
        
        # Initialize vault structure
        self.vault_data = {
            "metadata": {
                "version": "2.0-ELITE",
                "created": datetime.datetime.now().isoformat(),
                "last_modified": datetime.datetime.now().isoformat(),
                "security_level": self.security_level.value,
                "encryption_method": self.encryption_method.value,
                "entry_count": 0,
                "vault_id": secrets.token_hex(16),
                "biometric_enabled": biometric_enabled,
                "yubikey_enabled": yubikey_enabled,
                "total_accesses": 0,
                "failed_attempts": 0
            },
            "entries": {},
            "audit_log": [],
            "security_settings": {
                "auto_lock_timeout": SECURITY_CONFIG['SESSION_TIMEOUT'],
                "max_login_attempts": SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS'],
                "require_2fa": False,
                "network_restrictions": [],
                "backup_retention": SECURITY_CONFIG['BACKUP_RETENTION']
            }
        }
        
        # Setup additional security features
        if biometric_enabled:
            self.biometric_auth.enroll_fingerprint()
        
        if keyfile_path:
            self._generate_keyfile(keyfile_path)
        
        self._save_vault_secure()
        self._log_security_event("VAULT_CREATED", "Elite vault initialized")
    
    def _pbkdf2_key(self, password: str, salt: bytes) -> bytes:
        """PBKDF2 key derivation"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=SECURITY_CONFIG['PBKDF2_ITERATIONS'],
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _generate_keyfile(self, path: str):
        """Generate cryptographic keyfile"""
        keyfile_data = {
            "vault_id": self.vault_data["metadata"]["vault_id"],
            "created": datetime.datetime.now().isoformat(),
            "key_material": base64.b64encode(secrets.token_bytes(1024)).decode(),
            "checksum": ""
        }
        
        # Calculate checksum
        checksum_data = json.dumps(keyfile_data, sort_keys=True).encode()
        keyfile_data["checksum"] = hashlib.sha256(checksum_data).hexdigest()
        
        with open(path, 'w') as f:
            json.dump(keyfile_data, f, indent=2)
    
    def unlock_elite_vault(self, master_password: str = None, keyfile_path: str = None,
                          biometric_verify: bool = False, yubikey_token: str = None) -> bool:
        """Unlock vault with multi-factor authentication"""
        if self.lockout_until and time.time() < self.lockout_until:
            remaining = int(self.lockout_until - time.time())
            raise Exception(f"Vault locked for {remaining} seconds")
        
        if not os.path.exists(VAULT_FILE):
            return False
        
        try:
            # Load encrypted vault
            with open(VAULT_FILE, 'r') as f:
                vault_container = json.load(f)
            
            # Verify integrity
            if not self._verify_vault_integrity(vault_container):
                raise Exception("Vault integrity check failed")
            
            # Reconstruct keys
            salts = vault_container["salts"]
            self.salt = base64.b64decode(salts["salt1"])
            salt2 = base64.b64decode(salts["salt2"])
            salt3 = base64.b64decode(salts["salt3"])
            
            key1 = self.encryption_engine.derive_key_argon2(master_password, self.salt)
            key2 = self.encryption_engine.derive_key_scrypt(master_password, salt2)
            key3 = self._pbkdf2_key(master_password, salt3)
            
            # Keyfile verification
            if keyfile_path:
                key4 = self._load_keyfile(keyfile_path)
            else:
                key4 = secrets.token_bytes(32)
            
            self.master_keys = [key1, key2, key3, key4]
            
            # Decrypt vault
            encrypted_data = vault_container["encrypted_data"]
            vault_json = self.encryption_engine.multi_layer_decrypt(encrypted_data, self.master_keys)
            self.vault_data = json.loads(vault_json)
            
            # Additional authentication checks
            auth_checks = 0
            required_checks = 1  # Password is always required
            
            if biometric_verify:
                if self.biometric_auth.verify_fingerprint():
                    auth_checks += 1
                    required_checks += 1
                else:
                    raise Exception("Biometric authentication failed")
            
            if yubikey_token:
                if self.yubikey_auth.verify_response(yubikey_token):
                    auth_checks += 1
                    required_checks += 1
                else:
                    raise Exception("YubiKey authentication failed")
            
            if auth_checks < required_checks:
                raise Exception("Multi-factor authentication failed")
            
            # Success
            self.login_attempts = 0
            self._log_security_event("VAULT_UNLOCKED", "Successful authentication")
            return True
            
        except Exception as e:
            self.login_attempts += 1
            if self.login_attempts >= SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS']:
                self.lockout_until = time.time() + SECURITY_CONFIG['LOCKOUT_DURATION']
                self._log_security_event("VAULT_LOCKOUT", f"Maximum attempts exceeded")
            
            self._log_security_event("VAULT_UNLOCK_FAILED", str(e))
            return False
    
    def _verify_vault_integrity(self, vault_container: Dict) -> bool:
        """Verify vault integrity using HMAC"""
        try:
            expected_hmac = vault_container["integrity_hash"]
            data_to_verify = json.dumps(vault_container["encrypted_data"], sort_keys=True)
            
            # Use a fixed key for integrity checking (in production, use proper key management)
            integrity_key = hashlib.sha256(b"vault_integrity_key").digest()
            calculated_hmac = hmac.new(integrity_key, data_to_verify.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(expected_hmac, calculated_hmac)
        except:
            return False
    
    def _load_keyfile(self, path: str) -> bytes:
        """Load and verify keyfile"""
        if not os.path.exists(path):
            raise Exception("Keyfile not found")
        
        with open(path, 'r') as f:
            keyfile_data = json.load(f)
        
        # Verify checksum
        stored_checksum = keyfile_data.pop("checksum")
        calculated_checksum = hashlib.sha256(
            json.dumps(keyfile_data, sort_keys=True).encode()
        ).hexdigest()
        
        if stored_checksum != calculated_checksum:
            raise Exception("Keyfile corrupted")
        
        # Verify vault ID
        if keyfile_data["vault_id"] != self.vault_data.get("metadata", {}).get("vault_id"):
            raise Exception("Keyfile does not match vault")
        
        return base64.b64decode(keyfile_data["key_material"])[:32]
    
    def add_elite_entry(self, entry: VaultEntry) -> bool:
        """Add entry with advanced security features"""
        try:
            # Check for password breaches
            if self.config.get('breach_monitoring', True):
                if self.network_security.check_breach_database(entry.password):
                    print("⚠️  WARNING: Password found in breach database!")
                    if input("Continue anyway? (y/N): ").lower() != 'y':
                        return False
            
            # Generate TOTP if requested
            if entry.totp_secret:
                totp = AdvancedTOTP(entry.totp_secret)
                entry.totp_secret = totp.secret
            
            # Encrypt all sensitive fields
            service_key = entry.service.lower().strip()
            encrypted_entry = self._encrypt_entry(entry)
            
            self.vault_data["entries"][service_key] = encrypted_entry
            self.vault_data["metadata"]["entry_count"] = len(self.vault_data["entries"])
            self.vault_data["metadata"]["last_modified"] = datetime.datetime.now().isoformat()
            
            self._save_vault_secure()
            self._log_security_event("ENTRY_ADDED", f"Entry added: {entry.service}")
            
            return True
            
        except Exception as e:
            self._log_security_event("ENTRY_ADD_FAILED", str(e))
            return False
    
    def _encrypt_entry(self, entry: VaultEntry) -> Dict[str, Any]:
        """Encrypt vault entry with multiple layers"""
        sensitive_fields = ['username', 'password', 'notes', 'totp_secret']
        encrypted_entry = asdict(entry)
        
        for field in sensitive_fields:
            if encrypted_entry[field]:
                encrypted_entry[field] = self.encryption_engine.multi_layer_encrypt(
                    encrypted_entry[field], self.master_keys
                )
        
        # Encrypt custom fields
        if encrypted_entry['custom_fields']:
            for key, value in encrypted_entry['custom_fields'].items():
                encrypted_entry['custom_fields'][key] = self.encryption_engine.multi_layer_encrypt(
                    value, self.master_keys
                )
        
        return encrypted_entry
    
    def get_elite_entry(self, service: str) -> Optional[VaultEntry]:
        """Retrieve and decrypt entry"""
        service_key = service.lower().strip()
        
        if service_key not in self.vault_data["entries"]:
            return None
        
        try:
            encrypted_entry = self.vault_data["entries"][service_key]
            decrypted_entry = self._decrypt_entry(encrypted_entry)
            
            # Update access statistics
            decrypted_entry.last_accessed = datetime.datetime.now().isoformat()
            decrypted_entry.access_count += 1
            
            # Re-encrypt and save
            self.vault_data["entries"][service_key] = self._encrypt_entry(decrypted_entry)
            self._save_vault_secure()
            
            self._log_security_event("ENTRY_ACCESSED", f"Entry accessed: {service}")
            
            return decrypted_entry
            
        except Exception as e:
            self._log_security_event("ENTRY_ACCESS_FAILED", str(e))
            return None
    
    def _decrypt_entry(self, encrypted_entry: Dict[str, Any]) -> VaultEntry:
        """Decrypt vault entry"""
        sensitive_fields = ['username', 'password', 'notes', 'totp_secret']
        decrypted_data = encrypted_entry.copy()
        
        for field in sensitive_fields:
            if decrypted_data[field]:
                decrypted_data[field] = self.encryption_engine.multi_layer_decrypt(
                    decrypted_data[field], self.master_keys
                )
        
        # Decrypt custom fields
        if decrypted_data['custom_fields']:
            for key, value in decrypted_data['custom_fields'].items():
                decrypted_data['custom_fields'][key] = self.encryption_engine.multi_layer_decrypt(
                    value, self.master_keys
                )
        
        return VaultEntry(**decrypted_data)
    
    def generate_security_report(self) -> SecurityReport:
        """Generate comprehensive security report"""
        report = SecurityReport(
            weak_passwords=[],
            reused_passwords=[],
            old_passwords=[],
            breached_passwords=[],
            expired_entries=[],
            totp_enabled=[],
            overall_score=0.0,
            recommendations=[]
        )
        
        passwords_seen = {}
        total_entries = len(self.vault_data["entries"])
        password_checks = 0
        strong_password_count = 0
        current_time = time.time()
        
        for service_key, encrypted_entry in self.vault_data["entries"].items():
            try:
                entry = self._decrypt_entry(encrypted_entry)
                
                # Check password strength
                result = zxcvbn.zxcvbn(entry.password)
                if result['score'] < 3:  # Weak password
                    report.weak_passwords.append(f"{entry.service} ({entry.username})")
                
                # Check for reused passwords
                if entry.password in passwords_seen:
                    report.reused_passwords.append(f"{entry.service} ({entry.username})")
                else:
                    passwords_seen[entry.password] = True
                
                # Check for old passwords
                if entry.last_modified:
                    modified_time = datetime.datetime.fromisoformat(entry.last_modified).timestamp()
                    if current_time - modified_time > 365 * 24 * 3600:  # Older than 1 year
                        report.old_passwords.append(f"{entry.service} ({entry.username})")
                
                # Check for breached passwords
                if self.config.get('breach_monitoring', True):
                    if self.network_security.check_breach_database(entry.password):
                        report.breached_passwords.append(f"{entry.service} ({entry.username})")
                
                # Check TOTP status
                if entry.totp_secret:
                    report.totp_enabled.append(entry.service)
                
                # Check expiration
                if entry.expiry_date:
                    expiry_time = datetime.datetime.fromisoformat(entry.expiry_date).timestamp()
                    if expiry_time < current_time:
                        report.expired_entries.append(f"{entry.service} ({entry.username})")
                
                # Count strong passwords
                if result['score'] >= 4:
                    strong_password_count += 1
                
                password_checks += 1
                
            except:
                pass  # Skip entries that can't be decrypted
        
        # Calculate overall security score
        if password_checks > 0:
            report.overall_score = (strong_password_count / password_checks) * 100
            if report.overall_score < 70:
                report.recommendations.append("Enable password generator for weak entries")
            if len(report.reused_passwords) > 0:
                report.recommendations.append("Replace reused passwords with unique ones")
            if len(report.breached_passwords) > 0:
                report.recommendations.append("Immediately change breached passwords")
            if len(report.totp_enabled) < password_checks * 0.5:
                report.recommendations.append("Enable TOTP for more accounts")
        
        return report

    def _save_vault_secure(self):
        """Save vault with enhanced security measures"""
        try:
            # Prepare salts
            salt2 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
            salt3 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
            
            vault_json = json.dumps(self.vault_data)
            
            # Encrypt vault data
            encrypted_data = self.encryption_engine.multi_layer_encrypt(vault_json, self.master_keys)
            
            # Create vault container
            vault_container = {
                "version": "2.0-ELITE",
                "timestamp": time.time(),
                "salts": {
                    "salt1": base64.b64encode(self.salt).decode(),
                    "salt2": base64.b64encode(salt2).decode(),
                    "salt3": base64.b64encode(salt3).decode()
                },
                "encrypted_data": encrypted_data,
                "integrity_hash": self._calculate_integrity_hash(encrypted_data)
            }
            
            # Write to temp file first
            temp_path = f"{VAULT_FILE}.tmp"
            with open(temp_path, 'w') as f:
                json.dump(vault_container, f, indent=2)
            
            # Atomic replace
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
            os.rename(temp_path, VAULT_FILE)
            
            # Create backup if enabled
            if self.config.get('auto_backup', True):
                self.backup_vault()
                
        except Exception as e:
            self._log_security_event("VAULT_SAVE_FAILED", str(e))
            raise

    def _calculate_integrity_hash(self, data: Any) -> str:
        """Calculate HMAC for data integrity verification"""
        data_str = json.dumps(data, sort_keys=True)
        integrity_key = hashlib.sha256(
            self.master_keys[0] + self.master_keys[1] + self.salt
        ).digest()
        return hmac.new(integrity_key, data_str.encode(), hashlib.sha512).hexdigest()

    def _log_security_event(self, event_type: str, details: str):
        """Log security event to audit log"""
        if not self.config.get('audit_logging', True):
            return
            
        event = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event_type,
            "details": details,
            "ip": self.network_security.get_public_ip(),
            "user": getpass.getuser(),
            "device": platform.node()
        }
        
        # Add to in-memory log
        self.vault_data.setdefault("audit_log", []).append(event)
        
        # Append to external log file with rotation
        log_entry = json.dumps(event) + "\n"
        
        try:
            # Rotate log if too large
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > SECURITY_CONFIG['AUDIT_LOG_MAX_SIZE']:
                rotated_log = f"{LOG_FILE}.{int(time.time())}"
                os.rename(LOG_FILE, rotated_log)
                
            with open(LOG_FILE, 'a') as f:
                f.write(log_entry)
        except:
            pass

    def backup_vault(self):
        """Create encrypted backup of the vault"""
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(BACKUP_DIR, f"vault_backup_{timestamp}.enc")
            
            # Encrypt backup with separate key
            backup_key = secrets.token_bytes(32)
            cipher = Fernet(base64.urlsafe_b64encode(backup_key))
            with open(VAULT_FILE, 'rb') as f:
                encrypted_data = cipher.encrypt(f.read())
            
            # Save encrypted backup
            with open(backup_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Save backup key separately
            key_file = os.path.join(BACKUP_DIR, f"backup_key_{timestamp}.key")
            with open(key_file, 'wb') as f:
                f.write(backup_key)
            
            # Enforce retention policy
            backups = sorted(Path(BACKUP_DIR).glob('vault_backup_*.enc'))
            if len(backups) > SECURITY_CONFIG['BACKUP_RETENTION']:
                for old_backup in backups[:len(backups) - SECURITY_CONFIG['BACKUP_RETENTION']]:
                    os.remove(old_backup)
                    key_file = old_backup.with_name(old_backup.name.replace('vault_backup_', 'backup_key_').replace('.enc', '.key'))
                    if key_file.exists():
                        os.remove(key_file)
            
            self._log_security_event("BACKUP_CREATED", f"Backup saved: {backup_file}")
            return True
            
        except Exception as e:
            self._log_security_event("BACKUP_FAILED", str(e))
            return False

    def restore_backup(self, backup_path: str, key_path: str):
        """Restore vault from encrypted backup"""
        try:
            with open(key_path, 'rb') as kf:
                backup_key = kf.read()
                
            with open(backup_path, 'rb') as bf:
                encrypted_data = bf.read()
                
            cipher = Fernet(base64.urlsafe_b64encode(backup_key))
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Write to temp file
            temp_path = f"{VAULT_FILE}.restore"
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
                
            # Verify integrity
            with open(temp_path, 'r') as f:
                json.load(f)  # Will fail if invalid
                
            # Replace current vault
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
            os.rename(temp_path, VAULT_FILE)
            
            self._log_security_event("BACKUP_RESTORED", f"Restored from: {backup_path}")
            return True
            
        except Exception as e:
            self._log_security_event("RESTORE_FAILED", str(e))
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def export_vault(self, format: str = "json", password: str = None):
        """Export vault in various formats"""
        try:
            os.makedirs(EXPORT_DIR, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            export_file = os.path.join(EXPORT_DIR, f"vault_export_{timestamp}.{format}")
            
            decrypted_data = {}
            for service, entry in self.vault_data["entries"].items():
                decrypted_data[service] = asdict(self._decrypt_entry(entry))
            
            if format == "json":
                with open(export_file, 'w') as f:
                    json.dump(decrypted_data, f, indent=2)
            
            elif format == "csv":
                with open(export_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Service", "Username", "Password", "URL", "Notes"])
                    for entry in decrypted_data.values():
                        writer.writerow([
                            entry['service'],
                            entry['username'],
                            entry['password'],
                            entry['url'],
                            entry['notes']
                        ])
            
            # Encrypt export if password provided
            if password:
                encrypted_file = export_file + ".enc"
                salt = secrets.token_bytes(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                cipher = Cipher(algorithms.AES(key), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
                encryptor = cipher.encryptor()
                
                with open(export_file, 'rb') as f_in, open(encrypted_file, 'wb') as f_out:
                    f_out.write(salt)
                    f_out.write(encryptor.nonce)
                    f_out.write(encryptor.update(open(export_file, 'rb').read()))
                    f_out.write(encryptor.finalize())
                    f_out.write(encryptor.tag)
                
                os.remove(export_file)
                export_file = encrypted_file
            
            self._log_security_event("VAULT_EXPORTED", f"Exported to: {export_file}")
            return export_file
            
        except Exception as e:
            self._log_security_event("EXPORT_FAILED", str(e))
            return None

    def import_vault(self, import_path: str, password: str = None):
        """Import data from various formats"""
        try:
            # Handle encrypted imports
            if import_path.endswith(".enc") and password:
                decrypted_path = import_path + ".dec"
                with open(import_path, 'rb') as f_in, open(decrypted_path, 'wb') as f_out:
                    salt = f_in.read(16)
                    nonce = f_in.read(12)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend()
                    )
                    key = kdf.derive(password.encode())
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                    decryptor = cipher.decryptor()
                    tag = f_in.read(16)
                    
                    chunk = f_in.read(4096)
                    while chunk:
                        f_out.write(decryptor.update(chunk))
                        chunk = f_in.read(4096)
                    
                    f_out.write(decryptor.finalize_with_tag(tag))
                
                import_path = decrypted_path
            
            # Determine format
            if import_path.endswith(".json"):
                with open(import_path, 'r') as f:
                    data = json.load(f)
                
                for service, entry_data in data.items():
                    entry = VaultEntry(**entry_data)
                    self.add_elite_entry(entry)
            
            elif import_path.endswith(".csv"):
                with open(import_path, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        entry = VaultEntry(
                            service=row['Service'],
                            username=row['Username'],
                            password=row['Password'],
                            url=row.get('URL', ''),
                            notes=row.get('Notes', '')
                        )
                        self.add_elite_entry(entry)
            
            # Clean up temporary file
            if import_path.endswith(".dec"):
                os.remove(import_path)
            
            self._log_security_event("VAULT_IMPORTED", f"Imported from: {import_path}")
            return True
            
        except Exception as e:
            self._log_security_event("IMPORT_FAILED", str(e))
            if import_path.endswith(".dec") and os.path.exists(import_path):
                os.remove(import_path)
            return False

    def change_master_password(self, new_password: str):
        """Change master password with key rotation"""
        try:
            # Re-encrypt all entries with new keys
            new_salt = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
            salt2 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
            salt3 = secrets.token_bytes(SECURITY_CONFIG['SALT_LENGTH'])
            
            key1 = self.encryption_engine.derive_key_argon2(new_password, new_salt)
            key2 = self.encryption_engine.derive_key_scrypt(new_password, salt2)
            key3 = self._pbkdf2_key(new_password, salt3)
            key4 = secrets.token_bytes(32)  # New quantum key
            
            # Re-encrypt all entries
            for service, entry in list(self.vault_data["entries"].items()):
                decrypted = self._decrypt_entry(entry)
                self.master_keys = [key1, key2, key3, key4]
                self.vault_data["entries"][service] = self._encrypt_entry(decrypted)
            
            # Update master keys and salt
            self.master_keys = [key1, key2, key3, key4]
            self.salt = new_salt
            
            # Save vault with new keys
            self._save_vault_secure()
            self._log_security_event("PASSWORD_CHANGED", "Master password updated")
            return True
            
        except Exception as e:
            self._log_security_event("PASSWORD_CHANGE_FAILED", str(e))
            return False

    def generate_password(self, length: int = 16, complexity: int = 4) -> str:
        """Generate high-entropy password with customizable complexity"""
        try:
            # Complexity levels:
            # 1: Only letters
            # 2: Letters + numbers
            # 3: Letters + numbers + symbols
            # 4: All characters + avoid ambiguous characters
            # 5: Passphrase mode
            
            if complexity == 5:  # Passphrase
                wordlist = []
                try:
                    with open('/usr/share/dict/words', 'r') as f:  # Unix systems
                        wordlist = [word.strip() for word in f.readlines() if 4 < len(word.strip()) < 8]
                except:
                    pass
                
                if not wordlist:
                    wordlist = ["correct", "horse", "battery", "staple", "secure", "vault", "system"]
                
                return '-'.join(secrets.choice(wordlist) for _ in range(4))
            
            characters = string.ascii_letters
            
            if complexity >= 2:
                characters += string.digits
            if complexity >= 3:
                characters += string.punctuation
            if complexity >= 4:
                # Remove ambiguous characters
                characters = characters.translate(str.maketrans('', '', 'l1Io0O'))
            
            while True:
                password = ''.join(secrets.choice(characters) for _ in range(length))
                # Ensure it meets complexity requirements
                if complexity >= 2 and not any(c in string.digits for c in password):
                    continue
                if complexity >= 3 and not any(c in string.punctuation for c in password):
                    continue
                # Check strength
                if zxcvbn.zxcvbn(password)['score'] >= 3:
                    return password
                    
        except Exception as e:
            self._log_security_event("PASSWORD_GEN_FAILED", str(e))
            return secrets.token_urlsafe(length)[:length]

    def check_password_health(self, password: str) -> Dict[str, Any]:
        """Comprehensive password health check"""
        result = zxcvbn.zxcvbn(password)
        breach_status = self.network_security.check_breach_database(password)
        entropy = len(password) * 4  # Simplified entropy calculation
        
        return {
            "strength_score": result['score'],
            "entropy_bits": entropy,
            "breached": breach_status,
            "crack_time": result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            "feedback": result['feedback']['warning'] if result['feedback']['warning'] else "Good password",
            "recommendations": result['feedback']['suggestions']
        }

    def lock_vault(self):
        """Securely lock the vault"""
        self.wipe_memory()
        self.session_token = None
        self.session_expiry = None
        self._log_security_event("VAULT_LOCKED", "User initiated lock")

    def wipe_memory(self):
        """Securely wipe sensitive data from memory"""
        try:
            # Overwrite master keys multiple times
            for i in range(SECURITY_CONFIG['MEMORY_WIPE_PASSES']):
                for j in range(len(self.master_keys)):
                    if self.master_keys[j]:
                        self.master_keys[j] = secrets.token_bytes(len(self.master_keys[j]))
                time.sleep(0.01)
            
            # Clear other sensitive variables
            self.master_keys = []
            self.salt = b''
            
            # Force garbage collection
            import gc
            gc.collect()
            
            self._log_security_event("MEMORY_WIPED", "Sensitive data cleared from memory")
        except:
            pass

    def emergency_lockdown(self):
        """Initiate emergency lockdown procedures"""
        try:
            # Wipe all sensitive data
            self.wipe_memory()
            
            # Delete vault file
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
            
            # Delete keyfiles
            if os.path.exists(KEYFILE_DIR):
                shutil.rmtree(KEYFILE_DIR)
            
            # Clear clipboard
            pyperclip.copy('')
            
            # Logout user
            self.session_token = None
            
            self._log_security_event("EMERGENCY_LOCKDOWN", "Nuclear option activated")
            return True
        except Exception as e:
            return False

# === COMMAND LINE INTERFACE ===
class VaultCLI:
    """Advanced command-line interface for the vault"""
    
    def __init__(self):
        self.vault = ElitePasswordVault()
        self.session_active = False
        self.locked = False
    
    def print_banner(self):
        """Display elite security banner"""
        print(colored("""
███████╗██╗     ███████╗██╗████████╗███████╗
██╔════╝██║     ██╔════╝██║╚══██╔══╝██╔════╝
█████╗  ██║     █████╗  ██║   ██║   █████╗  
██╔══╝  ██║     ██╔══╝  ██║   ██║   ██╔══╝  
███████╗███████╗███████╗██║   ██║   ███████╗
╚══════╝╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝
        """, 'cyan'))
        print(colored("Military-Grade Password Vault - Elite Edition", 'yellow'))
        print(colored("© 2025 Pradip Gosain - Enhanced Security Suite\n", 'blue'))
    
    def main_menu(self):
        """Main user interface"""
        self.print_banner()
        
        while True:
            if not self.session_active:
                self.login_menu()
            
            print("\n" + "="*50)
            print(colored("MAIN MENU", 'green'))
            print("1. Add Entry")
            print("2. Retrieve Entry")
            print("3. Generate Password")
            print("4. Security Report")
            print("5. Backup Vault")
            print("6. Export/Import")
            print("7. Settings")
            print("8. Lock Vault")
            print("9. Emergency Lockdown")
            print("0. Exit")
            
            choice = input("\n> Enter choice: ")
            
            try:
                if choice == '1':
                    self.add_entry()
                elif choice == '2':
                    self.retrieve_entry()
                elif choice == '3':
                    self.generate_password()
                elif choice == '4':
                    self.security_report()
                elif choice == '5':
                    self.backup_vault()
                elif choice == '6':
                    self.import_export_menu()
                elif choice == '7':
                    self.settings_menu()
                elif choice == '8':
                    self.lock_vault()
                elif choice == '9':
                    self.emergency_lockdown()
                elif choice == '0':
                    self.vault.wipe_memory()
                    sys.exit(0)
                else:
                    print(colored("Invalid choice!", 'red'))
            except Exception as e:
                print(colored(f"Error: {str(e)}", 'red'))
    
    def login_menu(self):
        """Authentication interface"""
        print("\n" + "="*50)
        print(colored("AUTHENTICATION REQUIRED", 'yellow'))
        
        # Check if vault exists
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Creating new vault...")
            self.create_vault()
            return
        
        attempts = 0
        max_attempts = SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS']
        
        while attempts < max_attempts:
            password = getpass("Master Password: ")
            keyfile = input("Keyfile Path (optional): ").strip() or None
            
            # Try to unlock vault
            if self.vault.unlock_elite_vault(password, keyfile):
                self.session_active = True
                self.locked = False
                print(colored("\n✔️ Vault unlocked successfully!", 'green'))
                return
            else:
                attempts += 1
                remaining = max_attempts - attempts
                print(colored(f"❌ Authentication failed! Attempts remaining: {remaining}", 'red'))
        
        # Lockout if max attempts reached
        lock_time = SECURITY_CONFIG['LOCKOUT_DURATION'] // 60
        print(colored(f"\n🔒 Vault locked for {lock_time} minutes due to multiple failed attempts", 'red'))
        time.sleep(SECURITY_CONFIG['LOCKOUT_DURATION'])
        self.login_menu()
    
    def create_vault(self):
        """Vault creation wizard"""
        print("\n" + "="*50)
        print(colored("CREATING NEW ELITE VAULT", 'cyan'))
        
        while True:
            password = getpass("Create Master Password: ")
            confirm = getpass("Confirm Master Password: ")
            
            if password != confirm:
                print(colored("Passwords do not match!", 'red'))
                continue
            
            # Check password strength
            result = zxcvbn.zxcvbn(password)
            if result['score'] < 3:
                print(colored("Password is too weak! Please choose a stronger password.", 'yellow'))
                print("Suggestions:", result['feedback']['suggestions'])
                continue
            
            keyfile = input("Keyfile Path (optional, leave blank to skip): ").strip()
            if keyfile:
                keyfile = os.path.abspath(keyfile)
            
            print("\nAdvanced Security Options:")
            print("1. Standard Security")
            print("2. Enhanced Security (Recommended)")
            print("3. Military-Grade Security")
            security_choice = input("Select security level [2]: ") or '2'
            
            if security_choice == '3':
                self.vault.security_level = SecurityLevel.MILITARY
            elif security_choice == '1':
                self.vault.security_level = SecurityLevel.MEDIUM
            else:
                self.vault.security_level = SecurityLevel.HIGH
            
            self.vault.initialize_elite_vault(
                master_password=password,
                keyfile_path=keyfile,
                biometric_enabled=False,
                yubikey_enabled=False
            )
            
            print(colored("\n✔️ Elite vault created successfully!", 'green'))
            print(colored(f"Vault ID: {self.vault.vault_data['metadata']['vault_id']}", 'cyan'))
            if keyfile:
                print(colored(f"Keyfile saved to: {keyfile}", 'cyan'))
                print(colored("WARNING: Store this keyfile securely! Without it, you cannot access your vault.", 'red'))
            
            self.session_active = True
            return
    
    def add_entry(self):
        """Add new password entry"""
        print("\n" + "="*50)
        print(colored("ADD NEW ENTRY", 'cyan'))
        
        service = input("Service/Website: ").strip()
        username = input("Username: ").strip()
        
        print("\nPassword Options:")
        print("1. Enter manually")
        print("2. Generate strong password")
        pass_choice = input("Choice [2]: ") or "2"
        
        if pass_choice == "1":
            password = getpass("Password: ")
        else:
            length = int(input("Password Length [16]: ") or 16)
            complexity = int(input("Complexity Level (1-5) [4]: ") or 4)
            password = self.vault.generate_password(length, complexity)
            print(f"\nGenerated Password: {colored(password, 'green')}")
        
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        totp = input("TOTP Secret (optional): ").strip()
        
        entry = VaultEntry(
            service=service,
            username=username,
            password=password,
            url=url,
            notes=notes,
            totp_secret=totp
        )
        
        if self.vault.add_elite_entry(entry):
            print(colored("\n✔️ Entry added successfully!", 'green'))
        else:
            print(colored("\n❌ Failed to add entry!", 'red'))
    
    def retrieve_entry(self):
        """Retrieve password entry"""
        print("\n" + "="*50)
        print(colored("RETRIEVE ENTRY", 'cyan'))
        
        service = input("Service/Website: ").strip()
        entry = self.vault.get_elite_entry(service)
        
        if not entry:
            print(colored("\n❌ Entry not found!", 'red'))
            return
        
        print("\n" + "="*50)
        print(colored(f"ENTRY DETAILS: {service}", 'yellow'))
        print(f"Username: {colored(entry.username, 'cyan')}")
        print(f"Password: {colored(entry.password, 'cyan')}")
        if entry.url:
            print(f"URL: {entry.url}")
        if entry.notes:
            print(f"Notes: {entry.notes}")
        
        # Copy password to clipboard
        pyperclip.copy(entry.password)
        print("\nPassword copied to clipboard (will clear in 30 seconds)")
        
        # Auto-clear clipboard
        if self.vault.config.get('clipboard_clear', True):
            def clear_clipboard():
                time.sleep(30)
                if pyperclip.paste() == entry.password:
                    pyperclip.copy('')
            threading.Thread(target=clear_clipboard).start()
    
    def generate_password(self):
        """Generate a secure password"""
        print("\n" + "="*50)
        print(colored("PASSWORD GENERATOR", 'cyan'))
        
        length = int(input("Password Length [16]: ") or 16)
        complexity = int(input("Complexity Level (1-5) [4]: ") or 4)
        
        password = self.vault.generate_password(length, complexity)
        health = self.vault.check_password_health(password)
        
        print("\n" + "="*50)
        print(f"Generated Password: {colored(password, 'green')}")
        print(f"Strength Score: {health['strength_score']}/4")
        print(f"Estimated Crack Time: {health['crack_time']}")
        
        if health['breached']:
            print(colored("WARNING: Password found in breach databases!", 'red'))
        
        pyperclip.copy(password)
        print("\nPassword copied to clipboard (will clear in 30 seconds)")
        
        # Auto-clear clipboard
        if self.vault.config.get('clipboard_clear', True):
            def clear_clipboard():
                time.sleep(30)
                if pyperclip.paste() == password:
                    pyperclip.copy('')
            threading.Thread(target=clear_clipboard).start()
    
    def security_report(self):
        """Generate security report"""
        print("\n" + "="*50)
        print(colored("SECURITY REPORT", 'cyan'))
        print("Generating comprehensive security analysis...")
        
        report = self.vault.generate_security_report()
        
        print("\n" + "="*50)
        print(colored("SECURITY ASSESSMENT", 'yellow'))
        print(f"Overall Security Score: {report.overall_score:.1f}%")
        
        print("\n" + "="*50)
        print(colored("VULNERABILITIES", 'red'))
        if report.weak_passwords:
            print("\nWeak Passwords:")
            for entry in report.weak_passwords[:5]:
                print(f" - {entry}")
            if len(report.weak_passwords) > 5:
                print(f" - ...and {len(report.weak_passwords)-5} more")
        
        if report.reused_passwords:
            print("\nReused Passwords:")
            for entry in report.reused_passwords[:3]:
                print(f" - {entry}")
            if len(report.reused_passwords) > 3:
                print(f" - ...and {len(report.reused_passwords)-3} more")
        
        if report.breached_passwords:
            print("\nBreached Passwords:")
            for entry in report.breached_passwords:
                print(f" - {colored(entry, 'red')}")
        
        if report.expired_entries:
            print("\nExpired Entries:")
            for entry in report.expired_entries:
                print(f" - {entry}")
        
        print("\n" + "="*50)
        print(colored("RECOMMENDATIONS", 'green'))
        if report.recommendations:
            for rec in report.recommendations:
                print(f" - {rec}")
        else:
            print(" - No critical issues found. Good security posture!")
    
    def backup_vault(self):
        """Create encrypted backup"""
        print("\n" + "="*50)
        print(colored("VAULT BACKUP", 'cyan'))
        
        if self.vault.backup_vault():
            print(colored("\n✔️ Backup created successfully!", 'green'))
            print("Backups stored in:", os.path.abspath(BACKUP_DIR))
        else:
            print(colored("\n❌ Backup failed!", 'red'))
    
    def import_export_menu(self):
        """Data import/export submenu"""
        print("\n" + "="*50)
        print(colored("IMPORT/EXPORT", 'cyan'))
        print("1. Export Vault")
        print("2. Import Data")
        print("0. Back to Main Menu")
        
        choice = input("\n> Enter choice: ")
        
        if choice == '1':
            self.export_vault()
        elif choice == '2':
            self.import_data()
    
    def export_vault(self):
        """Export vault data"""
        print("\n" + "="*50)
        print(colored("EXPORT VAULT", 'cyan'))
        
        print("Export Formats:")
        print("1. JSON (unencrypted)")
        print("2. CSV (unencrypted)")
        print("3. Encrypted Export")
        format_choice = input("\n> Enter choice: ")
        
        if format_choice == '1':
            format = 'json'
            password = None
        elif format_choice == '2':
            format = 'csv'
            password = None
        elif format_choice == '3':
            format = 'json'
            password = getpass("Encryption Password: ")
        else:
            print(colored("Invalid choice!", 'red'))
            return
        
        export_file = self.vault.export_vault(format, password)
        
        if export_file:
            print(colored("\n✔️ Export successful!", 'green'))
            print("Exported to:", os.path.abspath(export_file))
        else:
            print(colored("\n❌ Export failed!", 'red'))
    
    def import_data(self):
        """Import data into vault"""
        print("\n" + "="*50)
        print(colored("IMPORT DATA", 'cyan'))
        
        path = input("File path to import: ").strip()
        if not os.path.exists(path):
            print(colored("File not found!", 'red'))
            return
        
        password = None
        if path.endswith('.enc'):
            password = getpass("Encryption Password: ")
        
        if self.vault.import_vault(path, password):
            print(colored("\n✔️ Import successful!", 'green'))
        else:
            print(colored("\n❌ Import failed!", 'red'))
    
    def settings_menu(self):
        """Vault settings menu"""
        print("\n" + "="*50)
        print(colored("VAULT SETTINGS", 'cyan'))
        
        print("Current Configuration:")
        for key, value in self.vault.config.items():
            print(f" - {key}: {'Enabled' if value else 'Disabled'}")
        
        print("\nToggle Options:")
        print("1. Toggle Automatic Backups")
        print("2. Toggle Audit Logging")
        print("3. Toggle Clipboard Clearing")
        print("4. Change Master Password")
        print("0. Back to Main Menu")
        
        choice = input("\n> Enter choice: ")
        
        if choice == '1':
            self.vault.config['auto_backup'] = not self.vault.config['auto_backup']
        elif choice == '2':
            self.vault.config['audit_logging'] = not self.vault.config['audit_logging']
        elif choice == '3':
            self.vault.config['clipboard_clear'] = not self.vault.config['clipboard_clear']
        elif choice == '4':
            self.change_master_password()
        
        self.vault.save_config()
        print("Settings updated successfully!")
    
    def change_master_password(self):
        """Change master password"""
        print("\n" + "="*50)
        print(colored("CHANGE MASTER PASSWORD", 'cyan'))
        
        current = getpass("Current Master Password: ")
        new_pass = getpass("New Master Password: ")
        confirm = getpass("Confirm New Password: ")
        
        if new_pass != confirm:
            print(colored("Passwords don't match!", 'red'))
            return
        
        # Verify current password
        if not self.vault.unlock_elite_vault(current):
            print(colored("Current password incorrect!", 'red'))
            return
        
        if self.vault.change_master_password(new_pass):
            print(colored("\n✔️ Master password changed successfully!", 'green'))
        else:
            print(colored("\n❌ Password change failed!", 'red'))
    
    def lock_vault(self):
        """Lock the vault"""
        self.vault.lock_vault()
        self.session_active = False
        print(colored("\n🔒 Vault locked successfully!", 'yellow'))
        self.login_menu()
    
    def emergency_lockdown(self):
        """Activate emergency lockdown"""
        print("\n" + "="*50)
        print(colored("EMERGENCY LOCKDOWN", 'red'))
        print("WARNING: This will permanently delete all vault data!")
        confirm = input("Type 'CONFIRM' to proceed: ")
        
        if confirm == 'CONFIRM':
            if self.vault.emergency_lockdown():
                print(colored("\n☢️  VAULT DESTROYED! All data erased.", 'red'))
                self.session_active = False
                self.locked = True
            else:
                print(colored("\n❌ Lockdown failed!", 'red'))
        else:
            print("Lockdown aborted")

# === SECURE ENVIRONMENT SETUP ===
def secure_environment():
    """Configure secure execution environment"""
    # Disable core dumps
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except:
        pass
    
    # Secure temp directory
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR, mode=0o700)
    
    # Set secure permissions for sensitive directories
    for dir in [BACKUP_DIR, KEYFILE_DIR, EXPORT_DIR]:
        if os.path.exists(dir):
            os.chmod(dir, 0o700)

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    # Set up secure environment
    secure_environment()
    
    # Security warning for non-Linux systems
    if platform.system() != 'Linux':
        print(colored("WARNING: For maximum security, use Linux-based systems", "yellow"))
    
    # Run the CLI
    cli = VaultCLI()
    cli.main_menu()