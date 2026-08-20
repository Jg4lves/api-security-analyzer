package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;
import java.util.List;

@Component
public class FingerprintAnalyzer {

    private static final List<String> IGNORED_GENERIC_SERVERS = List.of(
            "cloudflare", "gws", "amazon", "akamai", "vercel", "netlify", "awselb"
    );

    public void analyze(HttpHeaders headers, SecurityReport report) {

        headers.firstValue("Server").ifPresent(server -> {
            String lowerServer = server.toLowerCase();

            boolean containsVersion = server.matches(".*\\d.*");

            boolean isGenericCdn = IGNORED_GENERIC_SERVERS.stream().anyMatch(lowerServer::contains);

            if (containsVersion) {
                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "Header 'Server' exposto revelando versão da tecnologia: " + server,
                                "Revelar a versão exata do software permite que atacantes busquem rapidamente por vulnerabilidades conhecidas (CVEs) afetando esta versão específica.",
                                "Configure o servidor web (Nginx, Apache, IIS) para ocultar a versão no header (ex: 'server_tokens off' no Nginx)."
                        )
                );
            } else if (!isGenericCdn) {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Header 'Server' exposto: " + server,
                                "Revela o software do servidor web utilizado, reduzindo o esforço de reconhecimento de um atacante.",
                                "Se possível, remova ou ofusque o header 'Server' nas configurações do servidor web."
                        )
                );
            }
        });

        headers.firstValue("X-Powered-By").ifPresent(powered -> {

            boolean containsVersion = powered.matches(".*\\d.*");

            if (containsVersion) {
                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "Header 'X-Powered-By' vazando versão do backend: " + powered,
                                "Exprime o framework/linguagem e sua versão exata rodando no servidor (ex: PHP/7.4), permitindo ataques direcionados a vulnerabilidades da versão.",
                                "Desabilite a emissão do header 'X-Powered-By' nas configurações do seu framework ou linguagem (ex: 'expose_php = Off' no php.ini)."
                        )
                );
            } else {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Header 'X-Powered-By' exposto: " + powered,
                                "Revela o framework rodando no backend (ex: Express, ASP.NET), o que ajuda o atacante a mapear a stack tecnológica.",
                                "Remova o header 'X-Powered-By' via configuração da aplicação ou do proxy reverso."
                        )
                );
            }
        });
    }
}