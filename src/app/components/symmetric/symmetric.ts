import { Component, inject, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SymmetricCryptoService } from '../../services/symmetric-crypto';

@Component({
  selector: 'app-symmetric',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  templateUrl: './symmetric.html',
  styleUrl: './symmetric.css',
})
export class Symmetric {
  private readonly cryptoService = inject(SymmetricCryptoService);

  readonly operation = signal<'encrypt' | 'decrypt'>('encrypt');
  readonly showPassword = signal<boolean>(false);
  readonly isDragging = signal<boolean>(false);
  readonly selectedFile = signal<File | null>(null);
  readonly password = signal<string>('');
  readonly isProcessing = signal<boolean>(false);
  readonly statusMessage = signal<string>('');
  readonly errorMessage = signal<string>('');
  readonly completedFile = signal<{ blob: Blob; fileName: string } | null>(null);

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0] ?? null;
    this.selectedFile.set(file);
    this.statusMessage.set('');
    this.errorMessage.set('');
    this.completedFile.set(null);
  }

  setOperation(operation: 'encrypt' | 'decrypt'): void {
    this.operation.set(operation);
    this.statusMessage.set('');
    this.errorMessage.set('');
    this.completedFile.set(null);
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.isDragging.set(false);
    const file = event.dataTransfer?.files?.[0] ?? null;
    if (file && !this.isProcessing()) {
      this.selectedFile.set(file);
      this.statusMessage.set('');
      this.errorMessage.set('');
      this.completedFile.set(null);
    }
  }

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.isDragging.set(true);
  }

  onDragLeave(event: DragEvent): void {
    if (!((event.currentTarget as HTMLElement).contains(event.relatedTarget as Node | null))) {
      this.isDragging.set(false);
    }
  }

  runOperation(): void {
    if (this.operation() === 'encrypt') void this.onEncrypt();
    else void this.onDecrypt();
  }

  async onEncrypt(): Promise<void> {
    const file = this.selectedFile();
    const pass = this.password();

    if (!file || !pass) {
      this.errorMessage.set('Selecciona un documento e ingresa una contraseña.');
      return;
    }

    this.isProcessing.set(true);
    this.errorMessage.set('');
    this.statusMessage.set('Derivando clave PBKDF2 y cifrando con AES-256-GCM...');

    try {
      const encryptedBlob = await this.cryptoService.encryptFile(file, pass);
      this.completedFile.set({ blob: encryptedBlob, fileName: `${file.name}.enc` });
      this.triggerDownload(encryptedBlob, `${file.name}.enc`);
      this.statusMessage.set(`Documento cifrado y descargado como "${file.name}.enc".`);
    } catch (err) {
      this.errorMessage.set(err instanceof Error ? err.message : 'Error inesperado al cifrar.');
      this.statusMessage.set('');
    } finally {
      this.isProcessing.set(false);
    }
  }

  async onDecrypt(): Promise<void> {
    const file = this.selectedFile();
    const pass = this.password();

    if (!file || !pass) {
      this.errorMessage.set('Selecciona un archivo .enc e ingresa la contraseña original.');
      return;
    }

    this.isProcessing.set(true);
    this.errorMessage.set('');
    this.statusMessage.set('Verificando integridad GCM y descifrando documento...');

    try {
      const result = await this.cryptoService.decryptFile(file, pass);
      this.completedFile.set({ blob: result.blob, fileName: result.fileName });
      this.triggerDownload(result.blob, result.fileName);
      this.statusMessage.set(`Documento restaurado correctamente: "${result.fileName}".`);
    } catch (err) {
      this.errorMessage.set(err instanceof Error ? err.message : 'Error al descifrar.');
      this.statusMessage.set('');
    } finally {
      this.isProcessing.set(false);
    }
  }

  downloadCompletedFile(): void {
    const result = this.completedFile();
    if (result) this.triggerDownload(result.blob, result.fileName);
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
