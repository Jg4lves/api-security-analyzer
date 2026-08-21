import { Component, OnDestroy, ViewChild } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { SecurityReportComponent } from '../pdf/pdf';

export interface SecurityCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  severity: 'critical' | 'high' | 'medium' | 'low' ;
  description: string;
  value?: string;
}

export interface SecurityReport {
  url: string;
  score: number;
  checks: SecurityCheck[];
}

@Component({
  selector: 'app-security-analyzer',
  standalone: true,
  imports: [FormsModule, CommonModule, SecurityReportComponent],
  templateUrl: './analyzer.html',
  styleUrls: ['./analyzer.scss'],
})
export class SecurityAnalyzerComponent implements OnDestroy {
  @ViewChild(SecurityReportComponent) pdfGenerator!: SecurityReportComponent;
  private readonly API_BASE = 'http://localhost:8080/api/security';

  targetUrl = '';
  inputFocused = false;
  urlError = '';
  isScanning = false;
  isDownloading = false;
  progress = 0;
  progressLabel = 'Iniciando análise...';
  report: SecurityReport | null = null;

  private progressInterval: any;

  emptyPlaceholders = [
    { w: '65%', w2: '40%' },
    { w: '80%', w2: '55%' },
    { w: '50%', w2: '70%' },
    { w: '75%', w2: '35%' },
    { w: '60%', w2: '60%' },
    { w: '70%', w2: '45%' },
  ];

  constructor(private http: HttpClient) {}

  validateUrl(): boolean {
    this.urlError = '';
    if (!this.targetUrl.trim()) {
      this.urlError = 'Por favor, informe uma URL válida.';
      return false;
    }
    const domainRegex = /^(https?:\/\/)?([\w-]+\.)+[\w-]{2,}(\/.*)?$/;
    if (!domainRegex.test(this.targetUrl)) {
      this.urlError = 'Formato de URL inválido. Ex: exemplo.com.br';
      return false;
    }
    return true;
  }

  startScan(): void {
    if (!this.validateUrl()) return;
    if (this.isScanning) return;

    const fullUrl = this.targetUrl.startsWith('http')
      ? this.targetUrl
      : `https://${this.targetUrl}`;

    this.isScanning = true;
    this.report = null;
    this.progress = 0;
    this.simulateProgress();

    this.http.post<SecurityReport>(`${this.API_BASE}/scan`, { url: fullUrl }).subscribe({
      next: (data) => {
        this.stopProgress();
        this.progress = 100;
        setTimeout(() => {
          this.isScanning = false;
          this.report = data;
        }, 400);
      },
      error: (err) => {
        this.stopProgress();
        this.isScanning = false;
        this.urlError =
          err.status === 0
            ? 'Não foi possível conectar ao servidor. Verifique se o backend está rodando.'
            : `Erro ao analisar: ${err.error?.message || 'Tente novamente.'}`;
      },
    });
  }

  downloadReport(): void {
    if (this.isDownloading || !this.report || !this.pdfGenerator) return;

    this.isDownloading = true;

    setTimeout(() => {
      try {
        this.pdfGenerator.downloadPdf();
      } catch (error) {
        console.error('Erro ao gerar PDF', error);
        alert('Erro ao gerar o PDF localmente.');
      } finally {
        this.isDownloading = false;
      }
    }, 150);
  }

  resetScan(): void {
    this.report = null;
    this.targetUrl = '';
    this.urlError = '';
    this.progress = 0;
  }

  getScoreClass(): string {
    if (!this.report) return '';
    if (this.report.score >= 80) return 'score-good';
    if (this.report.score >= 50) return 'score-warn';
    return 'score-bad';
  }

  private simulateProgress(): void {
    const steps = [
      { target: 15, label: 'Resolvendo DNS...' },
      { target: 30, label: 'Conectando ao servidor...' },
      { target: 50, label: 'Verificando headers HTTP...' },
      { target: 65, label: 'Analisando certificado SSL...' },
      { target: 80, label: 'Verificando políticas de segurança...' },
      { target: 92, label: 'Gerando relatório...' },
    ];
    let stepIndex = 0;
    this.progressInterval = setInterval(() => {
      if (stepIndex < steps.length) {
        const step = steps[stepIndex];
        if (this.progress < step.target) {
          this.progress += 1;
          this.progressLabel = step.label;
        } else {
          stepIndex++;
        }
      }
    }, 80);
  }

  private stopProgress(): void {
    if (this.progressInterval) {
      clearInterval(this.progressInterval);
      this.progressInterval = null;
    }
    this.progressLabel = 'Concluído!';
  }

  ngOnDestroy(): void {
    this.stopProgress();
  }
}
