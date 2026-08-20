package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Component
public class SecurityTxtAnalyzer {

    private final HttpClient httpClient;

    public SecurityTxtAnalyzer(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void analyze(
            String baseUrl,
            SecurityReport report
    ) {

        try {
            String sanitizedBaseUrl = baseUrl.endsWith("/")
                    ? baseUrl.substring(0, baseUrl.length() - 1)
                    : baseUrl;

            String targetUrl = sanitizedBaseUrl + "/.well-known/security.txt";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() == 200) {

                String contentType = response.headers().firstValue("Content-Type").orElse("").toLowerCase();
                String body = response.body().toLowerCase();

                boolean isTextPlain = contentType.contains("text/plain");
                boolean hasContactField = body.contains("contact:");

                if (!isTextPlain && !hasContactField) {
                    report.addIssue(
                            new SecurityIssue(
                                    "LOW",
                                    "Arquivo 'security.txt' inválido ou ausente (Soft 404).",
                                    "O servidor retornou status 200, mas o conteúdo parece ser uma página HTML genérica em vez de um arquivo válido focado em VDP (Vulnerability Disclosure Policy).",
                                    "Crie o arquivo '/.well-known/security.txt' em formato texto puro (text/plain) contendo a tag obrigatória 'Contact:'."
                            )
                    );
                }

            } else {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Arquivo 'security.txt' não foi encontrado no servidor (Status: " + response.statusCode() + ").",
                                "A ausência do arquivo dificulta que pesquisadores de segurança éticos reportem vulnerabilidades diretamente para sua organização.",
                                "Crie o arquivo '/.well-known/security.txt' segundo a RFC 9116 contendo os canais oficiais de contato (Contact:)."
                        )
                );
            }

        } catch (Exception e) {

            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Não foi possível verificar a presença do arquivo 'security.txt'.",
                            "Falha de rede ou timeout durante a tentativa de consulta do caminho '/.well-known/security.txt'.",
                            "Certifique-se de que as rotas '.well-known' estão acessíveis e não bloqueadas por Firewalls (WAF) ou regras de redirecionamento."
                    )
            );
        }
    }
}