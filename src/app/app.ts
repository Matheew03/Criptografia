import { Component, signal } from '@angular/core';
import { Symmetric } from './components/symmetric/symmetric';
import { Asymmetric } from './components/asymmetric/asymmetric';

export type ActiveTab = 'symmetric' | 'asymmetric';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [Symmetric, Asymmetric],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  readonly activeTab = signal<ActiveTab>('symmetric');

  selectTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
  }
}