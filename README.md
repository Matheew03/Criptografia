# CryptoDoc — Sistema de Cifrado Zero-Knowledge en el Navegador

Aplicación web desarrollada en **Angular (Standalone Components + TypeScript)** para el cifrado y descifrado de documentos confidenciales bajo arquitectura **Client-Side Encryption (Zero-Knowledge)**. Todo el procesamiento criptográfico se ejecuta localmente en la memoria RAM del navegador sin enviar archivos, contraseñas ni llaves privadas a servidores externos.

---

## Características Principales

### 1. Cifrado Simétrico (`AES-256-GCM + PBKDF2`)
* **Algoritmo:** AES-256 en modo autenticado **GCM (*Galois/Counter Mode*)** mediante la API nativa `Web Crypto API` (`window.crypto.subtle`).
* **Derivación de claves:** **PBKDF2** con `SHA-256`, *Salt* aleatorio de 16 bytes y `310,000` iteraciones.
* **Protección de integridad:** Detección automática de manipulación de bits o contraseñas incorrectas mediante etiqueta de autenticación GCM (16 bytes).
* **Restauración exacta:** Empaquetado binario que conserva el nombre y extensión original del documento (`.pdf`, `.docx`, `.png`, `.txt`, etc.).

### 2. Cifrado Asimétrico (`OpenPGP / RSA-4096`)
* **Estándar:** Implementación compatible con **RFC 4880 (OpenPGP)** mediante `openpgp.js`, interoperable con **GnuPG y Kleopatra**.
* **Generación de certificados:** Creación de pares de llaves **RSA-4096** en formato *ASCII Armored* (`.asc`), cálculo de huella digital (*Fingerprint*) y protección de llave privada mediante *passphrase*.
* **Intercambio seguro:** Cifrado de documentos con llave pública (`.pgp`) y descifrado mediante llave privada y *passphrase* (compatible con archivos `.pgp` y `.gpg`).

---

## Arquitectura del Proyecto

```text
src/app/
├── services/
│   ├── symmetric-crypto.ts   # Lógica AES-256-GCM y derivación PBKDF2
│   └── openpgp.ts            # Generación RSA-4096, cifrado y descifrado OpenPGP
├── components/
│   ├── symmetric/            # Interfaz del módulo simétrico
│   └── asymmetric/           # Interfaz del generador de llaves y cifrado PGP
└── app.ts                    # Contenedor principal con navegación por señales (Signals)