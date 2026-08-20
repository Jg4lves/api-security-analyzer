package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;
import java.util.List;

@Component
public class HeaderAnalyzer {
    private static final List<String> HSTS_PRELOAD_KNOWN_DOMAINS = List.of(
            "google.com", "www.google.com", "github.com", "cloudflare.com"
    );

    public void analyze(HttpHeaders headers, SecurityReport report) {
        String contentType = headers.firstValue("Content-Type").orElse("").toLowerCase();
        boolean isHtml = contentType.contains("text/html") || contentType.isEmpty();

        String csp = headers.firstValue("Content-Security-Policy").orElse("");
        boolean hasCspHeader = !csp.isEmpty();

        if (!hasCspHeader && isHtml) {
            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Header 'Content-Security-Policy' ausente.",
                            "Sem uma política CSP via Header HTTP, páginas HTML ficam significativamente mais vulneráveis a ataques de Cross-Site Scripting (XSS) e injeção de dados.",
                            "Configure o header 'Content-Security-Policy' restringindo as origens permitidas para scripts e recursos externos."
                    )
            );
        }

        boolean hasHsts = headers.firstValue("Strict-Transport-Security").isPresent();
        if (!hasHsts) {
            boolean isKnownPreload = HSTS_PRELOAD_KNOWN_DOMAINS.stream().anyMatch(report.getUrl()::contains);

            String severity = isKnownPreload ? "LOW" : "HIGH";
            String impact = isKnownPreload
                    ? "O header HSTS não foi enviado diretamente na resposta, mas o domínio é amplamente conhecido por estar na HSTS Preload List dos navegadores."
                    : "A ausência do HSTS permite que atacantes forçam a conexão do usuário a cair para HTTP inseguro (Downgrade Attacks).";

            report.addIssue(
                    new SecurityIssue(
                            severity,
                            "Header 'Strict-Transport-Security' (HSTS) ausente.",
                            impact,
                            "Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' para impor conexões HTTPS no navegador."
                    )
            );
        }

        boolean hasFrameAncestors = csp.toLowerCase().contains("frame-ancestors");
        if (headers.firstValue("X-Frame-Options").isEmpty() && !hasFrameAncestors && isHtml) {
            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Proteção contra Clickjacking ausente (X-Frame-Options ou CSP frame-ancestors).",
                            "A página pode ser embutida dentro de um <iframe> em sites maliciosos, expondo os usuários a cliques falsificados.",
                            "Configure o header 'X-Frame-Options' para 'DENY' ou adicione a diretiva 'frame-ancestors' na política do CSP."
                    )
            );
        }

        if (headers.firstValue("X-Content-Type-Options").isEmpty()) {
            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Header 'X-Content-Type-Options' ausente.",
                            "Navegadores podem tentar adivinhar o tipo de conteúdo (MIME Sniffing), podendo executar arquivos/dados enviados por usuários como se fossem scripts.",
                            "Adicione o header 'X-Content-Type-Options: nosniff' para forçar o navegador a respeitar o Content-Type declarado pelo servidor."
                    )
            );
        }

        if (isHtml) {
            if (headers.firstValue("Referrer-Policy").isEmpty()) {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Header 'Referrer-Policy' ausente.",
                                "O navegador pode enviar URLs completas contendo parâmetros sensíveis no header Referer ao navegar para links externos.",
                                "Defina o header 'Referrer-Policy' para 'strict-origin-when-cross-origin' ou 'no-referrer'."
                        )
                );
            }

            if (headers.firstValue("Permissions-Policy").isEmpty()) {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Header 'Permissions-Policy' ausente.",
                                "Recursos do navegador (câmera, microfone, geolocalização) permanecem com o comportamento de acesso padrão.",
                                "Adicione o header 'Permissions-Policy' desabilitando recursos do dispositivo que não são utilizados pela aplicação."
                        )
                );
            }
        }
    }
}