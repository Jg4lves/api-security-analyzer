package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

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

            if (location.startsWith("http://")) {

                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "Redirecionamento para um endpoint HTTP inseguro.",
                                "A aplicação está redirecionando o tráfego do usuário para uma URL não criptografada, permitindo a interceptação ou manipulação de dados por ataques Man-in-the-Middle (MitM).",
                                "Ganta que todos os redirecionamentos no header 'Location' utilizem estritamente o protocolo seguro HTTPS (ex: https://...)."
                        )
                );
            }
        }
    }
}