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

            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(
                                    URI.create(
                                            baseUrl +
                                                    "/.well-known/security.txt"
                                    )
                            )
                            .GET()
                            .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if (response.statusCode() != 200) {

                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "Arquivo 'security.txt' não foi encontrado no servidor.",
                                "A ausência do arquivo dificulta que pesquisadores e éticos de segurança reportem vulnerabilidades encontradas de forma segura e direta para sua organização.",
                                "Crie o arquivo '/.well-known/security.txt' segundo a RFC 9116 contendo os canais oficiais de contato de segurança (Contact:) e prazo de suporte (Expires:)."
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