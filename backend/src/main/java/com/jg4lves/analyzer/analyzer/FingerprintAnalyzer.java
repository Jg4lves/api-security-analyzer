package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class FingerprintAnalyzer {

    public void analyze(
            HttpHeaders headers,
            SecurityReport report
    ) {

        headers.firstValue("Server")
                .ifPresent(server -> {
                    report.addIssue(
                            new SecurityIssue(
                                    "LOW",
                                    "Header 'Server' exposto: " + server,
                                    "Revela o software do servidor web e/ou versão utilizada, facilitando o mapeamento de vulnerabilidades conhecidas por um atacante.",
                                    "Configure o servidor web (Nginx, Apache, IIS, etc.) para remover ou ocultar o header 'Server'."
                            )
                    );
                });

        headers.firstValue("X-Powered-By")
                .ifPresent(powered -> {
                    report.addIssue(
                            new SecurityIssue(
                                    "LOW",
                                    "Header 'X-Powered-By' exposto: " + powered,
                                    "Exprime o framework ou linguagem rodando no backend (ex: Express, PHP, ASP.NET), reduzindo o esforço de reconhecimento de um atacante.",
                                    "Desabilite a emissão do header 'X-Powered-By' nas configurações do seu framework ou servidor de aplicação."
                            )
                    );
                });
    }
}