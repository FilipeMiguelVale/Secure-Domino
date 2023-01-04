import logging
import getpass
import PyKCS11
from PyKCS11 import PyKCS11Error, PyKCS11Lib, Mechanism
from cryptography import x509
from cryptography.exceptions import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from OpenSSL import crypto
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error,\
                    X509Store, X509StoreContextError, X509StoreFlags, X509StoreContextError
from os import listdir
from time import sleep
import json
import base64
import os
import subprocess


"""
Based on :  github.com/pyca/cryptography
            github.com/pyca/pyopenssl
            github.com/LudovicRousseau/PyKCS11
            github.com/luminoso/chatsecure/blob/master/M2/PKCS11_Wrapper.py   
            github.com/Jpfonseca/Blockchain_auction_management/blob/master/src/grabcrls.sh
            cryptography.io/en/2.7/x509/reference/      
"""

if os.name == "posix":
    lib = '/usr/local/lib/libpteidpkcs11.so'
elif os.name == "nt":
    lib = 'c:\\Windows\\System32\\pteidpkcs11.dll'



class CitizenCard:
    
    
    # Init
    def __init__(self):
        
        self.cert=None
      
        # Load all Certificates and CRL's 
        rootCerts, authCerts, crls = self.loadCertsCRLs()
        
        # CC Store Context 
        self.ccStoreContext = self.ccStoreContext(rootCerts, authCerts, crls)

        # List Open Sessions
        self.sessions = self.openSessions()
        
        # Get all Citizen Cards Names
        self.fullNames = self.getCCardsNames()
      
        
    # Convert all cert and crl files in PEM or ASN1 
    def loadCertsCRLs(self):
        
        # Update CRL's
        #subprocess.call(['sh', './getCRLs.sh'])
        
        rootCerts = ()
        authCerts = ()
        crls = ()

        # Cetificates and CRL's folders
        folder = ["certs/", "crls/"]

        # Root and Authentication Certificates
        for fileName in listdir(folder[0]):
            try:
                certInfo = open(folder[0] + fileName, 'rb').read()
                
            except Error:
                logging.error("Error Loading File!")
                return None, None, None
                
            else:                
                if ".crt" in fileName or ".der" in fileName:
                    try:
                        if "ca_ecc" in fileName:
                            rootCert = load_certificate(FILETYPE_PEM, certInfo)
                        elif "-self" in fileName:
                            rootCert = load_certificate(FILETYPE_PEM, certInfo)
                        else:
                            rootCert = load_certificate(FILETYPE_ASN1, certInfo)
                            
                    except Error:
                        logging.error("Error Loading Certificate!")
                        return None, None, None
                    else:
                        rootCerts = rootCerts + (rootCert,)
                        
                elif ".cer" in fileName:
                    try:
                        if "0012" in fileName or "0013" in fileName or "0015" in fileName:
                            authCert = load_certificate(FILETYPE_PEM, certInfo)                            
                        else:
                            authCert = load_certificate(FILETYPE_ASN1, certInfo)
                            
                    except Error:
                        logging.error("Error Loading Certificate!")
                        return None, None, None
              
                    else:
                        authCerts = authCerts + (authCert,)

        print("\nLoaded Root Certificates : {:d} out of {:d} ".format(len(rootCerts), len(listdir(folder[0]))))
        print("Loaded Authentication Certificates: {:d} out of {:d} ".format(len(authCerts), len(listdir(folder[0]))))

        # CRL's 
        for fileName in listdir(folder[1]):
            try:
                crlInfo = open(folder[1] + "/" + fileName, 'rb').read()
                
            except Error:
                logging.error("Error Loading File")
                return None, None, None
            else:
                if ".crl" in fileName:
                    crl = load_crl(FILETYPE_ASN1, crlInfo)
                    crls = crls + (crl,)
        
        print("Loaded Certificate Revocation Lists: {:d} out of {:d} \n".format(len(crls), len(listdir(folder[1]))))
        
        return rootCerts, authCerts, crls
    
    
    # Store Context (X509StoreContext) to validate a Citizen Card 
    def ccStoreContext(self, rootCerts, authCerts, crls):

        try:
            # Create Stored Context
            ccStoreContext = X509Store()
            
            # Root Certificates
            numRoot = 0
            
            # Authentication Certificates
            numAuth = 0
            
            # Certificates Revocation Lists
            numCRLs = 0
            
            for rootCert in rootCerts:
                ccStoreContext.add_cert(rootCert)
                numRoot += 1
            print("Root Certificates added to the X509StoreContext: {:d}".format(numRoot))
            
            for authCert in authCerts:
                ccStoreContext.add_cert(authCert)
                numAuth += 1
            print("Authentication Certificates added to the X509StoreContext: {:d}".format(numAuth))
            
            for crl in crls:
                ccStoreContext.add_crl(crl)
                numCRLs += 1
            print("Certificates Revocation Lists added to the X509StoreContext: {:d}\n".format(numCRLs))

            ccStoreContext.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
            
        except X509StoreContextError:
            logging.error("Store Context Failed!")
            return None
        else:
            return ccStoreContext
      
        
    # List Open Sessions
    def openSessions(self):

        try:
            # Initialize PyKCS11 
            pkcs11 = PyKCS11Lib()
            pkcs11.load(lib)
            
            # List of all Card Slots
            self.cardSlots = pkcs11.getSlotList(tokenPresent=True)
            
            # If there are no Card Slots
            if len(self.cardSlots) < 1:
                logging.error("CC Not Found, insert it and try again!")
                return []
                
            # List of all Open Sessions  
            return [pkcs11.openSession(self.cardSlots[slot]) for slot in range(0, len(self.cardSlots))]
        
        except Error:
            logging.error("CC Not Found, insert it and try again!")
            return []
        
    
    # Get ID of the CC Session Player
    def getCCID(self, sessionNum):
        
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        try:
            # Get Description
            description = self.sessions[sessionNum].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
           
            # Get Subject String to extract ID
            subject = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in description][0])
            
        except PyKCS11Error:
            logging.error("Card: {:3d} session interrupted!".format(sessionNum))
            return None
        else:
            id = subject.split("BI")[1][:8]
            return id
        
    # Get Full Name of the CC Session Player
    def getCCName(self, sessionNum):
        
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        try:
            # Get Description
            description = self.sessions[sessionNum].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])) 
            # Get Subject String to extract Full Name
            subject = ''.join(chr(code) for code in [code.to_dict()['CKA_SUBJECT'] for code in description][0])
            
        except PyKCS11Error:
            logging.error("Card: {:3d} session interrupted!".format(sessionNum))
            return None
        else:
            names = subject.split("BI")[1].split("\x0c")
            return ' '.join(names[name][1:] for name in range(1, len(names)))


    # Get Certificate of the CC Player
    def getCCCert(self, player):
    
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        try:
            description = self.sessions[player].findObjects(
            template    = ([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), 
                            (PyKCS11.CKA_LABEL, AUTH_CERT_LABEL)]))
            
        except:
            logging.error("Player Card: {:3d} session interrupted".format(player))
            return None
        else:
            try:
                derValue = bytes([code.to_dict()['CKA_VALUE'] for code in description][0])

            except IndexError:
                logging.error("Certificate Not Found!")
                return None
            else: 
                try:
                    # Convert DER to X509
                    cert = x509.load_der_x509_certificate(derValue, default_backend()).public_bytes(Encoding.PEM)
                    
                except Error:
                    logging.error("Error loading certificate of CC: {:2d}\n".format(player))
                    return None
                else: 
                    # Deserialize a certificate from PEM encoded data
                    self.cert = x509.load_pem_x509_certificate(cert, default_backend())
                    return cert


    # Get all Citizen Cards Names
    def getCCardsNames(self):
        
        try:
            allNames = [self.getCCName(i) for i in self.cardSlots]
        except Error:
            logging.error("Error getting all Citizen Cards Names!")
            return None
        else:
            return allNames
    

    # Validate Certificate in the Chain of Trust
    def validateChain(self, pemCert):
        storeContext = None
        
        if pemCert is None:
            return None

        try:
            # Convert PEM to X509
            cert = load_certificate(FILETYPE_PEM, pemCert)
            print("\nCertificate Loaded!")
            
            # Store Context (X509StoreContext) to verify a Certificate
            storeContext = crypto.X509StoreContext(self.ccStoreContext, cert).verify_certificate()
            print("Certificate Stored!")
            
        except X509StoreContextError:
            logging.error("Error verifying the Certificate for the StoreContext!")
            return False
        except Error:
            logging.error("No Certificate was loaded!")
            return False

        if storeContext is None:
            print("Citizen Card Verified!")
            return True
        else:
            return False

    
    # Sign Data with CC Private Key
    def signData(self, data, player):
        
        # Get Session
        session = self.sessions[player]

        if isinstance(data, str):
            try:
                # Get CC Private Key
                privateKey = self.sessions[player].findObjects(
                template = ([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")]))[0]
                
                # Sign Data
                signedData = session.sign(privateKey, data.encode(), Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, ""))
                
            except PyKCS11Error:
                logging.error("Card: {:3d} session interrupted!".format(player))
            else:
                print("\nPlayer{:3d} signed \"{:15s}\" with this Signature: {}".format(player, data, bytes(signedData)))
                return bytes(signedData)
        return None

    # Signature Verification
    def signatureVerification(self, data, cert, signature):
        
        # Deserialize a certificate from PEM encoded data
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        
        # Extract Public Key from Certificate
        publicKey = cert.public_key()
        
        # Padding
        padding = _aspaadding.PKCS1v15()

        if not isinstance(publicKey, rsa.RSAPublicKey):
            logging.error("No Public Key Found!")
            return False
        try:
             # Generates a verification context from the given Public Key and Signature
            verifier = publicKey.verify(
                signature,
                bytes(data.encode()),
                padding,
                hashes.SHA256(),
            )

        except InvalidSignature:
            # Signature is not from the owner of the CC that provided this Certificate
            logging.error("Invalid Signature!")
            return False
        else:
            # Signature is from the owner of the CC that provided this Certificate
            print("Signature Verified!")
            return True


    # LOGIN
    def login(self, player):
        
        session = self.sessions[player]
        name = self.fullNames[player]
        
        # CC Session PIN
        pin = None
        
        while True:
            pin = getpass.getpass('Auth PIN (CITIZEN CARD): ')
            
            if (len(pin) != 4) or not pin.isdigit():
                print("PIN Invalid! Try again (PIN with 4 digits)\n")
            else:
                try:
                    if name == self.getCCardsNames()[player]:
                        session.login(pin)
                except PyKCS11Error:
                    logging.error("Failed to Login with CC: {:d}".format(player))
                    return False
                else:
                    sleep(2)
                    print("\nLogin made with Player {:d} - \"{:15s}\"".format(player, name))
                    return True


    # LOGOUT
    def logout(self, player):
        # Logout session for current player
        session = self.sessions[player]
        session.logout()
        session.closeSession()


