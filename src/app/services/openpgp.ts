import { Injectable } from '@angular/core';
import * as openpgp from 'openpgp';

export interface GeneratedKeyPair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
  userId: string;
}

export interface PgpDecryptedFileResult {
  blob: Blob;
  fileName: string;
}

@Injectable({
  providedIn: 'root'
})
export class OpenpgpService {
  async generateKeyPair(
    name: string,
    email: string,
    passphrase: string
  ): Promise<GeneratedKeyPair> {
    const cleanName = name.trim();
    const cleanEmail = email.trim();

    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'rsa',
      rsaBits: 4096,
      userIDs: [{ name: cleanName, email: cleanEmail }],
      passphrase,
      format: 'armored'
    });

    const parsedPublicKey = await openpgp.readKey({ armoredKey: publicKey });
    const fingerprint = parsedPublicKey.getFingerprint().toUpperCase();

    return {
      publicKey,
      privateKey,
      fingerprint,
      userId: `${cleanName} <${cleanEmail}>`
    };
  }

  async encryptFileWithPublicKey(file: File, armoredPublicKey: string): Promise<Blob> {
    const cleanKey = armoredPublicKey.trim();
    if (!cleanKey) {
      throw new Error('Debes proporcionar una llave pública OpenPGP (.asc).');
    }

    let publicKey: openpgp.Key;
    try {
      publicKey = await openpgp.readKey({ armoredKey: cleanKey });
    } catch {
      throw new Error('La llave pública no tiene un formato OpenPGP válido.');
    }

    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const message = await openpgp.createMessage({
      binary: fileBytes,
      filename: file.name
    });

    const encryptedData = await openpgp.encrypt({
      message,
      encryptionKeys: publicKey,
      format: 'binary'
    });

    return new Blob([encryptedData as BlobPart], { type: 'application/pgp-encrypted' });
  }

  async decryptFileWithPrivateKey(
    encryptedFile: File,
    armoredPrivateKey: string,
    passphrase: string
  ): Promise<PgpDecryptedFileResult> {
    const cleanKey = armoredPrivateKey.trim();
    if (!cleanKey) {
      throw new Error('Debes proporcionar tu llave privada OpenPGP (.asc).');
    }

    let privateKey: openpgp.PrivateKey;
    try {
      const parsedKey = await openpgp.readPrivateKey({ armoredKey: cleanKey });
      privateKey = await openpgp.decryptKey({
        privateKey: parsedKey,
        passphrase
      });
    } catch {
      throw new Error('Llave privada inválida o passphrase incorrecta.');
    }

    const encryptedBytes = new Uint8Array(await encryptedFile.arrayBuffer());
    let message: openpgp.Message<Uint8Array>;
    try {
      message = await openpgp.readMessage({ binaryMessage: encryptedBytes });
    } catch {
      // Si el archivo viene en formato ASCII Armored (.asc) en lugar de binario (.pgp/.gpg)
      const armoredText = new TextDecoder().decode(encryptedBytes);
      message = await openpgp.readMessage({ armoredMessage: armoredText }) as unknown as openpgp.Message<Uint8Array>;
    }

    try {
      const decrypted = await openpgp.decrypt({
        message,
        decryptionKeys: privateKey,
        format: 'binary'
      });

      const fallbackName = encryptedFile.name.replace(/\.(pgp|gpg|asc)$/i, '') || 'documento_descifrado';
      const restoredName = decrypted.filename || fallbackName;

      return {
        blob: new Blob([decrypted.data as BlobPart], { type: 'application/octet-stream' }),
        fileName: restoredName
      };
    } catch {
      throw new Error('No se pudo descifrar el documento. Verifica que corresponda a esta llave privada.');
    }
  }
}