import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { GeneratedKeyPair, OpenpgpService } from '../../services/openpgp';

@Component({
  selector: 'app-asymmetric',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './asymmetric.html',
  styleUrl: './asymmetric.css'
})
export class Asymmetric {
  private readonly openpgpService = inject(OpenpgpService);

  // Sección 1: Generación de llaves
  readonly name = signal<string>('');
  readonly email = signal<string>('');
  readonly passphrase = signal<string>('');
  readonly isGenerating = signal<boolean>(false);
  readonly keyPair = signal<GeneratedKeyPair | null>(null);
  readonly keyGenError = signal<string>('');

  // Sección 2: Cifrar con Llave Pública
  readonly fileToEncrypt = signal<File | null>(null);
  readonly recipientPublicKey = signal<string>('');
  readonly isEncrypting = signal<boolean>(false);
  readonly encryptStatus = signal<string>('');
  readonly encryptError = signal<string>('');

  // Sección 3: Descifrar con Llave Privada
  readonly fileToDecrypt = signal<File | null>(null);
  readonly userPrivateKey = signal<string>('');
  readonly decryptPassphrase = signal<string>('');
  readonly isDecrypting = signal<boolean>(false);
  readonly decryptStatus = signal<string>('');
  readonly decryptError = signal<string>('');

  async onGenerateKeys(): Promise<void> {
    const userName = this.name().trim();
    const userEmail = this.email().trim();
    const pass = this.passphrase();

    if (!userName || !userEmail || !pass) {
      this.keyGenError.set('Completa tu nombre, correo y una passphrase para generar el par de llaves.');
      return;
    }

    this.isGenerating.set(true);
    this.keyGenError.set('');
    this.keyPair.set(null);

    try {
      const result = await this.openpgpService.generateKeyPair(userName, userEmail, pass);
      this.keyPair.set(result);
    } catch (err) {
      this.keyGenError.set(err instanceof Error ? err.message : 'Error al generar llaves OpenPGP.');
    } finally {
      this.isGenerating.set(false);
    }
  }

  downloadKey(type: 'public' | 'private'): void {
    const current = this.keyPair();
    if (!current) return;

    const content = type === 'public' ? current.publicKey : current.privateKey;
    const fileName = type === 'public' ? 'public_key.asc' : 'private_key.asc';

    this.triggerDownload(new Blob([content], { type: 'text/plain;charset=utf-8' }), fileName);
  }

  useGeneratedKeysForTesting(): void {
    const current = this.keyPair();
    if (!current) return;
    this.recipientPublicKey.set(current.publicKey);
    this.userPrivateKey.set(current.privateKey);
    this.decryptPassphrase.set(this.passphrase());
  }

  onEncryptFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.fileToEncrypt.set(input.files?.[0] ?? null);
    this.encryptStatus.set('');
    this.encryptError.set('');
  }

  async onPublicKeyFileSelected(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    this.recipientPublicKey.set(await file.text());
  }

  async onEncryptDocument(): Promise<void> {
    const file = this.fileToEncrypt();
    const pubKey = this.recipientPublicKey();

    if (!file || !pubKey.trim()) {
      this.encryptError.set('Selecciona un documento y carga o pega la llave pública del destinatario.');
      return;
    }

    this.isEncrypting.set(true);
    this.encryptError.set('');
    this.encryptStatus.set('Cifrando documento con OpenPGP...');

    try {
      const encryptedBlob = await this.openpgpService.encryptFileWithPublicKey(file, pubKey);
      const outputName = `${file.name}.pgp`;
      this.triggerDownload(encryptedBlob, outputName);
      this.encryptStatus.set(`Archivo cifrado como "${outputName}". Puedes abrirlo aquí o en Kleopatra.`);
    } catch (err) {
      this.encryptError.set(err instanceof Error ? err.message : 'Error al cifrar documento.');
      this.encryptStatus.set('');
    } finally {
      this.isEncrypting.set(false);
    }
  }

  onDecryptFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.fileToDecrypt.set(input.files?.[0] ?? null);
    this.decryptStatus.set('');
    this.decryptError.set('');
  }

  async onPrivateKeyFileSelected(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    this.userPrivateKey.set(await file.text());
  }

  async onDecryptDocument(): Promise<void> {
    const file = this.fileToDecrypt();
    const privKey = this.userPrivateKey();
    const pass = this.decryptPassphrase();

    if (!file || !privKey.trim() || !pass) {
      this.decryptError.set('Selecciona el archivo .pgp, carga tu llave privada e ingresa tu passphrase.');
      return;
    }

    this.isDecrypting.set(true);
    this.decryptError.set('');
    this.decryptStatus.set('Desbloqueando llave privada y descifrando documento...');

    try {
      const result = await this.openpgpService.decryptFileWithPrivateKey(file, privKey, pass);
      this.triggerDownload(result.blob, result.fileName);
      this.decryptStatus.set(`Documento restaurado correctamente: "${result.fileName}".`);
    } catch (err) {
      this.decryptError.set(err instanceof Error ? err.message : 'Error al descifrar documento.');
      this.decryptStatus.set('');
    } finally {
      this.isDecrypting.set(false);
    }
  }

  private triggerDownload(blob: Blob, fileName: string): void {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }
}