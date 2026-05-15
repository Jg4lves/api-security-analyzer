import { Component } from '@angular/core';
import { SecurityAnalyzerComponent } from './components/analyzer/analyzer';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [SecurityAnalyzerComponent],
  template: `<app-security-analyzer></app-security-analyzer>`,
})
export class AppComponent {}