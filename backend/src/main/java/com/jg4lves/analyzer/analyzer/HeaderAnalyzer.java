package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class HeaderAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {
        if (headers.firstValue("Content-Security-Policy").isEmpty()) {
            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Header 'Content-Security-Policy' ausente.",
                            "Sem uma política CSP, a aplicação fica significativamente mais vulnerável a ataques de Cross-Site Scripting (XSS) e injeção de dados.",
                            "Configure o header 'Content-Security-Policy' restringindo as origens permitidas para scripts, estilos e recursos externos (ex: default-src 'self')."
                    )
            );
        }

        if (headers.firstValue("Strict-Transport-Security").isEmpty()) {
            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Header 'Strict-Transport-Security' (HSTS) ausente.",
                            "A ausência do HSTS permite que atacantes forcem a conexão do usuário a cair para HTTP inseguro (Downgrade Attacks / SSL Stripping).",
                            "Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' para impor conexões HTTPS no navegador."
                    )
            );
        }

        if (headers.firstValue("X-Frame-Options").isEmpty()) {
            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Header 'X-Frame-Options' ausente.",
                            "A página pode ser embutida dentro de um <iframe> em sites maliciosos, expondo os usuários a ataques de Clickjacking.",
                            "Configure o header 'X-Frame-Options' com o valor 'DENY' ou 'SAMEORIGIN' (ou use a diretiva frame-ancestors no CSP)."
                    )
            );
        }

        if (headers.firstValue("X-Content-Type-Options").isEmpty()) {
            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Header 'X-Content-Type-Options' ausente.",
                            "Navegadores podem tentar adivinhar o tipo de conteúdo (MIME Sniffing), executando arquivos enviados por usuários como se fossem scripts ou HTML.",
                            "Adicione o header 'X-Content-Type-Options: nosniff' para forçar o navegador a respeitar o Content-Type declarado pelo servidor."
                    )
            );
        }

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
                            "Recursos do navegador e da API do dispositivo (câmera, microfone, geolocalização) permanecem com o comportamento padrão do navegador embutido.",
                            "Adicione o header 'Permissions-Policy' desabilitando recursos não utilizados na aplicação (ex: geolocation=(), camera=(), microphone=())."
                    )
            );
        }
    }
}