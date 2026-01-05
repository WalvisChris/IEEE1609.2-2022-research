import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from typing import Optional
import time

class DemoUtilities:
    """
    Beheert de generatie en het laden van een EC (SECP256R1) sleutelpaar.
    De sleutels zijn beschikbaar als publieke attributen: .private_key en .public_key
    """
    
    KEY_DIR = "keys/"
    PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
    PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")
    CURVE = ec.SECP256R1()

    def __init__(self):
        # Publieke attributen (aanvankelijk None)
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self._start_time = None
        
        # Probeer direct te laden, anders moeten ze gegenereerd worden
        if not self._load_keys():
            print("INFO: Sleutelbestanden niet gevonden. Roep generate_keys() aan om ze te maken.")

    def _load_keys(self) -> bool:
        """
        Interne functie om keys te laden uit bestanden.
        Geeft True terug als beide keys succesvol zijn geladen.
        """
        try:
            # 1. Private Key Laden
            with open(self.PRIVATE_KEY_FILE, "rb") as f:
                private_pem_bytes = f.read()
            
            self.private_key = serialization.load_pem_private_key(
                private_pem_bytes,
                password=None,
                backend=default_backend()
            )
            
            # 2. Public Key Laden
            with open(self.PUBLIC_KEY_FILE, "rb") as f:
                public_pem_bytes = f.read()

            self.public_key = serialization.load_pem_public_key(
                public_pem_bytes,
                backend=default_backend()
            )
            
            #print("INFO: Private en public key succesvol geladen.")
            return True

        except FileNotFoundError:
            return False # Bestanden bestaan niet, dus laden mislukt

    def generate_keys(self):
        """
        Genereert een nieuw sleutelpaar, slaat ze op in de keys/ directory
        en stelt de publieke attributen in.
        """
        
        # 1. Maak de map aan
        os.makedirs(self.KEY_DIR, exist_ok=True)
        
        # 2. Genereer de keys
        private_key = ec.generate_private_key(self.CURVE)
        public_key = private_key.public_key()

        # 3. Private Key Opslaan
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        with open(self.PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_pem)
        print("private key aangemaakt")

        # 4. Public Key Opslaan
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_pem)
        print("public key aangemaakt")
        
        # 5. Publieke attributen instellen
        self.private_key = private_key
        self.public_key = public_key
        
        print("INFO: De nieuwe sleutels zijn beschikbaar via keys.private_key en keys.public_key.")

    def send_message(self, msg: bytes):
        with open("ieeeMessage.txt", "wb") as f:
            f.write(msg)
    
    def read_message(self):
        with open("ieeeMessage.txt", "rb") as f:
            return f.read()
    
    def start_timer(self):
        """Start de timer vanaf het huidige moment"""
        self._start_time = time.time()

    def get_time(self):
        """Geeft de verstreken tijd in seconden sinds start_timer"""
        if self._start_time is None:
            raise ValueError("Timer is nog niet gestart. Gebruik start_timer() eerst.")
        return time.time() - self._start_time

# _ = DemoUtilities()
# _.generate_keys()