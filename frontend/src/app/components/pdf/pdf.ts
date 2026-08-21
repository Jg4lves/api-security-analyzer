import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import pdfMake from 'pdfmake/build/pdfmake';
import pdfFonts from 'pdfmake/build/vfs_fonts';
import { Content, TDocumentDefinitions, Style } from 'pdfmake/interfaces';

const vfsCandidate =
  (pdfFonts as any)?.vfs ??
  (pdfFonts as any)?.pdfMake?.vfs ??
  (pdfFonts as any)?.default?.vfs ??
  (pdfFonts as any)?.default?.pdfMake?.vfs;

if (vfsCandidate) {
  (pdfMake as any).vfs = vfsCandidate;
} else {
  console.error(
    '[SecurityReport] Não foi possível localizar o vfs do pdfmake. ' +
      'Verifique a versão de "pdfmake" instalada e o formato de export de "vfs_fonts".'
  );
}

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  severity: Severity | string;
  description: string;
  impact: string;
  recommendation: string;
}

export interface SecurityReport {
  target: string;
  riskScore: number;
  overallSeverity: Severity | string;
  findings: Finding[];
  generatedAt?: Date;
}

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; bar: string }> = {
  HIGH:   { bg: '#FDECEC', text: '#C0152F', bar: '#E4363F' },
  MEDIUM: { bg: '#FFF4E5', text: '#B45F06', bar: '#F5A623' },
  LOW:    { bg: '#EAF3FF', text: '#1F5FBF', bar: '#3B82F6' },
};

const FALLBACK_COLOR = { bg: '#F3F4F6', text: '#4B5563', bar: '#9CA3AF' };

const SEVERITY_LABEL_PT: Record<Severity, string> = {
  HIGH: 'ALTA',
  MEDIUM: 'MÉDIA',
  LOW: 'BAIXA',
};

function normalizeSeverity(value: Severity | string | null | undefined): Severity {
  const normalized = String(value ?? '').trim().toUpperCase();
  if (normalized === 'HIGH' || normalized === 'MEDIUM' || normalized === 'LOW') {
    return normalized;
  }
  return 'LOW'; 
}

function colorFor(sev: Severity | string): { bg: string; text: string; bar: string } {
  const key = normalizeSeverity(sev);
  return SEVERITY_COLORS[key] ?? FALLBACK_COLOR;
}

function labelFor(sev: Severity | string): string {
  const key = normalizeSeverity(sev);
  return SEVERITY_LABEL_PT[key] ?? String(sev ?? 'N/A').toUpperCase();
}

@Component({
  selector: 'app-security-report',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './pdf.html',
  styleUrls: ['./pdf.scss'],
})
export class SecurityReportComponent {
  report!: SecurityReport;

  @Input() set sourceData(analyzerData: any) {
    if (!analyzerData) return;

    try {
      const rawIssues = Array.isArray(analyzerData.issues) ? analyzerData.issues 
                      : Array.isArray(analyzerData.checks) ? analyzerData.checks 
                      : [];

      this.report = {
        target: analyzerData.url || 'URL não informada',
        riskScore: analyzerData.score || 0,
        overallSeverity: this.getOverallSeverity(analyzerData.score || 0),
        generatedAt: new Date(),
        
        findings: rawIssues.map((issue: any) => ({
          severity: this.mapSeverity(issue.severity),
          description: issue.description ||'Sem título',
          impact: issue.impact || 'Sem descrição detalhada',
          recommendation: issue.recommendation || 'Nenhuma recomendação adicional.'
        }))
      };
      
    } catch (error) {
      console.error('Erro ao montar os dados do PDF:', error);
    }
  }

  private getOverallSeverity(score: number): Severity {
    if (score < 50) return 'HIGH';
    if (score < 80) return 'MEDIUM';
    return 'LOW';
  }

  private mapSeverity(analyzerSeverity: string): Severity {
    const sev = analyzerSeverity?.toLowerCase();
    if (sev === 'critical' || sev === 'high') return 'HIGH';
    if (sev === 'medium') return 'MEDIUM';
    return 'LOW';
  }

  colorFor = colorFor;
  labelFor = labelFor;

  readonly severities: Severity[] = ['HIGH', 'MEDIUM', 'LOW'];

  countBy(sev: Severity): number {
    if (!this.report || !this.report.findings) return 0;
    return this.report.findings.filter((f) => normalizeSeverity(f.severity) === sev).length;
  }

  downloadPdf(): void {
    if (!this.report) {
      console.error('Tentativa de baixar PDF, mas o this.report está undefined.');
      alert('Os dados do relatório ainda estão sendo processados ou houve um erro na resposta da API. Verifique o console.');
      return;
    }

    const docDefinition = this.buildDocDefinition(this.report);
    const fileName = `relatorio-seguranca-${this.sanitizeFileName(this.report.target)}.pdf`;
    pdfMake.createPdf(docDefinition).download(fileName);
  }

  openPdfInNewTab(): void {
    if (!this.report) return;
    const docDefinition = this.buildDocDefinition(this.report);
    pdfMake.createPdf(docDefinition).open();
  }

  private sanitizeFileName(value: string): string {
    if (!value) return 'analise';
    return value.replace(/https?:\/\//g, '').replace(/[^a-z0-9]+/gi, '-');
  }

  private buildDocDefinition(report: SecurityReport): TDocumentDefinitions {
    const overall = colorFor(report.overallSeverity);
    const dateStr = (report.generatedAt ?? new Date()).toLocaleString('pt-BR');

    const content: Content[] = [
      {
        columns: [
          {
            width: '*',
            stack: [
              { text: 'Relatório de Análise de Segurança', style: 'title' },
              { text: 'Security Analysis Report', style: 'subtitle' },
            ],
          },
          {
            width: 'auto',
            stack: [
              {
                text: 'RISK SCORE',
                style: 'riskLabel',
                alignment: 'right',
              },
              {
                text: `${report.riskScore}`,
                style: 'riskScore',
                alignment: 'right',
                color: overall.bar,
              },
            ],
          },
        ],
      },
      { canvas: [{ type: 'line', x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1.5, lineColor: '#E5E7EB' }], margin: [0, 8, 0, 16] },

      {
        table: {
          widths: ['33%', '33%', '*'],
          body: [
            [
              { text: 'ALVO', style: 'infoLabel' },
              { text: 'SEVERIDADE GERAL', style: 'infoLabel' },
              { text: 'DATA DA ANÁLISE', style: 'infoLabel' },
            ],
            [
              { text: report.target, style: 'infoValue' },
              {
                text: labelFor(report.overallSeverity),
                style: 'infoValue',
                color: overall.bar,
                bold: true,
              },
              { text: dateStr, style: 'infoValue' },
            ],
          ],
        },
        layout: 'noBorders',
        margin: [0, 0, 0, 20],
      },

      {
        columns: this.severities.map((sev) => ({
          width: '*',
          margin: [0, 0, 8, 0],
          table: {
            widths: ['*'],
            body: [
              [
                {
                  stack: [
                    { text: labelFor(sev), style: 'summaryLabel', color: colorFor(sev).text },
                    { text: `${this.countBy(sev)}`, style: 'summaryCount', color: colorFor(sev).bar },
                  ],
                  fillColor: colorFor(sev).bg,
                  margin: [10, 8, 10, 8],
                },
              ],
            ],
          },
          layout: 'noBorders',
        })),
        margin: [0, 0, 0, 24],
      },

      { text: 'Achados Detalhados', style: 'sectionTitle', margin: [0, 0, 0, 10] },

      ...report.findings.flatMap((f, idx) => this.buildFindingBlock(f, idx)),
    ];

    return {
      pageSize: 'A4',
      pageMargins: [40, 50, 40, 60],
      content,
      styles: this.styles(),
      defaultStyle: { font: 'Roboto', fontSize: 9.5, color: '#1F2937' },
      footer: (currentPage: number, pageCount: number) => ({
        columns: [
          { text: 'Gerado automaticamente • Confidencial', style: 'footerText', margin: [40, 0, 0, 0] },
          { text: `${currentPage} / ${pageCount}`, style: 'footerText', alignment: 'right', margin: [0, 0, 40, 0] },
        ],
      }),
    };
  }

  private buildFindingBlock(finding: Finding, index: number): Content[] {
    const colors = colorFor(finding.severity);

    return [
      {
        unbreakable: true,
        margin: [0, 0, 0, 14],
        table: {
          widths: [6, '*'],
          body: [
            [
              {
                text: '',
                fillColor: colors.bar,
                border: [false, false, false, false],
              },
              {
                border: [false, false, false, false],
                fillColor: '#F9FAFB',
                margin: [12, 10, 12, 10],
                stack: [
                  {
                    columns: [
                      {
                        width: '*',
                        text: `${index + 1}. ${finding.description}`,
                        style: 'findingTitle',
                      },
                      {
                        width: 'auto',
                        text: labelFor(finding.severity),
                        style: 'badge',
                        color: colors.text,
                        fillColor: colors.bg,
                        margin: [8, 2, 8, 2],
                      },
                    ],
                  },
                  { text: 'IMPACTO', style: 'fieldLabel', margin: [0, 10, 0, 2] },
                  { text: finding.impact, style: 'fieldValue' },
                  { text: 'RECOMENDAÇÃO', style: 'fieldLabel', margin: [0, 8, 0, 2] },
                  { text: finding.recommendation, style: 'fieldValue' },
                ],
              },
            ],
          ],
        },
        layout: {
          hLineWidth: () => 0,
          vLineWidth: () => 0,
          paddingLeft: () => 0,
          paddingRight: () => 0,
          paddingTop: () => 0,
          paddingBottom: () => 0,
        },
      },
    ];
  }

  private styles(): Record<string, Style> {
    return {
      title: { fontSize: 18, bold: true, color: '#111827' },
      subtitle: { fontSize: 10, color: '#6B7280', margin: [0, 2, 0, 0] },
      riskLabel: { fontSize: 8, color: '#6B7280', characterSpacing: 1 },
      riskScore: { fontSize: 26, bold: true, margin: [0, 2, 0, 0] },
      infoLabel: { fontSize: 8, color: '#9CA3AF', bold: true, characterSpacing: 0.5, margin: [0, 0, 0, 4] },
      infoValue: { fontSize: 10.5, color: '#111827', margin: [0, 0, 0, 2] },
      summaryLabel: { fontSize: 8, bold: true, characterSpacing: 0.5 },
      summaryCount: { fontSize: 18, bold: true, margin: [0, 2, 0, 0] },
      sectionTitle: { fontSize: 13, bold: true, color: '#111827' },
      findingTitle: { fontSize: 10.5, bold: true, color: '#111827' },
      badge: { fontSize: 7.5, bold: true, characterSpacing: 0.5 },
      fieldLabel: { fontSize: 7.5, bold: true, color: '#9CA3AF', characterSpacing: 0.5 },
      fieldValue: { fontSize: 9.5, color: '#374151', lineHeight: 1.3 },
      footerText: { fontSize: 7.5, color: '#9CA3AF' },
    };
  }
}