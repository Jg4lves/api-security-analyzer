package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class CorsAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {

        String allowOrigin = headers.firstValue("Access-Control-Allow-Origin").orElse("");
        String allowCredentials = headers.firstValue("Access-Control-Allow-Credentials").orElse("");

        if (allowOrigin.equals("*")) {

            if (allowCredentials.equalsIgnoreCase("true")) {
                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "CORS com wildcard (*) e Allow-Credentials igual a 'true'.",
                                "Navegadores modernos bloqueiam essa combinação. Isso indica uma má configuração de segurança que pode quebrar a aplicação.",
                                "Para aceitar credenciais (cookies/tokens), remova o '*' e defina as origens específicas permitidas."
                        )
                );
            } else {
                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "CORS está configurado permitindo qualquer origem com wildcard (*).",
                                "Se este endpoint retornar dados sensíveis/privados, sites de terceiros poderão lê-los. (Se for uma API pública ou CDN, isso é o comportamento esperado).",
                                "Verifique se a rota lida com dados privados. Caso positivo, substitua o '*' por origens explícitas."
                        )
                );
            }
        }

        if (allowOrigin.equals("null")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "CORS está configurado permitindo a origem 'null'.",
                            "A origem 'null' pode ser gerada intencionalmente por atacantes usando iframes em sandbox (sandbox iframes) ou arquivos locais para contornar proteções e roubar dados.",
                            "Nunca utilize 'null' como valor para Access-Control-Allow-Origin. Especifique os domínios confiáveis."
                    )
            );
        }
    }
}