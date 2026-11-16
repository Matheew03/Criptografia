import { Injectable } from '@angular/core';

export interface DecryptedFileResult {
  blob: Blob;
  fileName: string;
}

@Injectable({
  providedIn: 'root',
})
export class SymmetricCryptoService {
  private readonly PBKDF2_ITERATIONS = 310_000;
  private readonly SALT_LENGTH = 16;
  private readonly IV_LENGTH = 12;

  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  async encryptFile(file: File, password: string): Promise<Blob> {
    const salt = window.crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    const iv = window.crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const aesKey = await this.deriveKey(password, salt);

    const fileBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuffer);

    // Empaquetamos nombre y MIME original dentro del payload cifrado
    const metadataJson = JSON.stringify({
      name: file.name,
      type: file.type || 'application/octet-stream',
    });
    const metadataBytes = new TextEncoder().encode(metadataJson);
    const metaLengthBytes = new Uint8Array(4);
    new DataView(metaLengthBytes.buffer).setUint32(0, metadataBytes.length, false);

    const payload = new Uint8Array(4 + metadataBytes.length + fileBytes.length);
    payload.set(metaLengthBytes, 0);
    payload.set(metadataBytes, 4);
    payload.set(fileBytes, 4 + metadataBytes.length);

    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      aesKey,
      payload,
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);

    // Estructura final: [Salt 16B] + [IV 12B] + [Ciphertext + AuthTag 16B]
    const output = new Uint8Array(this.SALT_LENGTH + this.IV_LENGTH + encryptedBytes.length);
    output.set(salt, 0);
    output.set(iv, this.SALT_LENGTH);
    output.set(encryptedBytes, this.SALT_LENGTH + this.IV_LENGTH);

    return new Blob([output], { type: 'application/octet-stream' });
  }

  async decryptFile(encryptedFile: File, password: string): Promise<DecryptedFileResult> {
    const fullBuffer = await encryptedFile.arrayBuffer();
    const fullBytes = new Uint8Array(fullBuffer);

    if (fullBytes.length < this.SALT_LENGTH + this.IV_LENGTH + 16) {
      throw new Error('El archivo está corrupto o no tiene un formato cifrado válido.');
    }

    const salt = fullBytes.slice(0, this.SALT_LENGTH);
    const iv = fullBytes.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
    const ciphertext = fullBytes.slice(this.SALT_LENGTH + this.IV_LENGTH);

    const aesKey = await this.deriveKey(password, salt);

    let decryptedBuffer: ArrayBuffer;
    try {
      decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        aesKey,
        ciphertext,
      );
    } catch {
      throw new Error(
        'Contraseña incorrecta o el archivo cifrado fue alterado (falló autenticación GCM).',
      );
    }

    const decryptedBytes = new Uint8Array(decryptedBuffer);
    const metaLength = new DataView(decryptedBytes.buffer).getUint32(0, false);
    const metadataBytes = decryptedBytes.slice(4, 4 + metaLength);
    const originalFileBytes = decryptedBytes.slice(4 + metaLength);

    const metadata = JSON.parse(new TextDecoder().decode(metadataBytes)) as {
      name: string;
      type: string;
    };

    return {
      blob: new Blob([originalFileBytes], { type: metadata.type }),
      fileName: metadata.name,
    };
  }
}
