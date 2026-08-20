package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class CorsAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {

        String cors = headers
                .firstValue("Access-Control-Allow-Origin")
                .orElse("");

        if (cors.equals("*")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "CORS está configurado permitindo qualquer origem com wildcard (*).",
                            "Qualquer site malicioso aberto no navegador do usuário pode fazer requisições para a sua API e ler os dados de resposta.",
                            "Substitua o caractere coringa '*' por uma lista explícita de origens permitidas ou remova o header se o recurso não precisar ser exposto a domínios de terceiros."
                    )
            );
        }
    }
}