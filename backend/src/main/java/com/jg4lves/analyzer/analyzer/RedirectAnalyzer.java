package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpResponse;

@Component
public class RedirectAnalyzer {

    public void analyze(
            HttpResponse<?> response,
            SecurityReport report
    ) {

        int status = response.statusCode();

        if (status == 301 || status == 302 || status == 307 || status == 308) {

            String location = response.headers()
                    .firstValue("Location")
                    .orElse("");

            if (location.isEmpty()) {
                return;
            }

            boolean isHttp = location.startsWith("http://");
            boolean isLocalhost = location.contains("localhost") || location.contains("127.0.0.1");

            if (isHttp && !isLocalhost) {
                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "Redirecionamento para um endpoint HTTP inseguro.",
                                "A aplicação está redirecionando o tráfego do usuário para uma URL não criptografada, permitindo a interceptação ou manipulação de dados por ataques Man-in-the-Middle (MitM).",
                                "Garanta que todos os redirecionamentos no header 'Location' utilizem estritamente o protocolo seguro HTTPS (ex: https://...)."
                        )
                );
            }

            if (location.startsWith("http://") || location.startsWith("https://")) {
                try {
                    URI originalUri = response.uri();
                    URI destinationUri = URI.create(location);

                    String originalHost = originalUri.getHost();
                    String destinationHost = destinationUri.getHost();

                    if (destinationHost != null && originalHost != null && !destinationHost.equalsIgnoreCase(originalHost)) {
                        report.addIssue(
                                new SecurityIssue(
                                        "LOW",
                                        "Redirecionamento para domínio externo detectado.",
                                        "O servidor está redirecionando o usuário para outro domínio (" + destinationHost + "). Se esse destino for construído com base em inputs do usuário (ex: ?url=...), a aplicação pode estar vulnerável a Open Redirect (Phishing).",
                                        "Valide se este redirecionamento é esperado (ex: gateway de pagamento). Caso seja dinâmico, utilize uma 'allowlist' estrita de domínios permitidos."
                                )
                        );
                    }
                } catch (IllegalArgumentException e) {
                }
            }
        }
    }
}