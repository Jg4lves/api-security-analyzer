package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.HttpCookie;
import java.net.http.HttpHeaders;
import java.util.List;

@Component
public class CookieAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {
        List<String> setCookieHeaders = headers.allValues("Set-Cookie");

        for (String headerValue : setCookieHeaders) {
            try {
                List<HttpCookie> cookies = HttpCookie.parse(headerValue);

                for (HttpCookie cookie : cookies) {
                    analyzeIndividualCookie(cookie, headerValue, report);
                }
            } catch (IllegalArgumentException e) {
                report.addIssue(new SecurityIssue(
                        "LOW",
                        "Header Set-Cookie com formato inválido.",
                        "Servidores ou clientes podem interpretar os cookies de forma inconsistente.",
                        "Revise a sintaxe do header Set-Cookie enviado pelo servidor: " + headerValue
                ));
            }
        }
    }

    private void analyzeIndividualCookie(HttpCookie cookie, String rawHeader, SecurityReport report) {
        String cookieName = cookie.getName();

        if (!cookie.isHttpOnly()) {
            report.addIssue(new SecurityIssue(
                    "HIGH",
                    String.format("O cookie '%s' não possui a flag 'HttpOnly'.", cookieName),
                    "Scripts executados no navegador (ex: via XSS) podem acessar o valor deste cookie e roubar sessões de usuários.",
                    "Adicione o atributo 'HttpOnly' ao definir o cookie no backend."
            ));
        }

        if (!cookie.getSecure()) {
            report.addIssue(new SecurityIssue(
                    "HIGH",
                    String.format("O cookie '%s' não possui a flag 'Secure'.", cookieName),
                    "O cookie será enviado pelo navegador através de conexões HTTP não criptografadas, ficando exposto a ataques Man-in-the-Middle (MitM).",
                    "Adicione a flag 'Secure' ao cookie para garantir que ele trafegue apenas via HTTPS."
            ));
        }

        String rawHeaderLowerCase = rawHeader.toLowerCase();

        if (!rawHeaderLowerCase.contains("samesite=")) {
            report.addIssue(new SecurityIssue(
                    "MEDIUM",
                    String.format("O cookie '%s' não define o atributo 'SameSite'.", cookieName),
                    "Sem o SameSite explicitado, o cookie pode ser enviado em requisições cross-site desnecessárias, facilitando ataques de CSRF.",
                    "Configure o atributo 'SameSite' como 'Lax' ou 'Strict' por padrão."
            ));
        } else if (rawHeaderLowerCase.contains("samesite=none") && !cookie.getSecure()) {
            report.addIssue(new SecurityIssue(
                    "HIGH",
                    String.format("O cookie '%s' possui SameSite=None, mas não usa a flag 'Secure'.", cookieName),
                    "Navegadores modernos bloqueiam cookies com SameSite=None enviados em conexões HTTP inseguras, o que pode quebrar a aplicação e gerar falhas de segurança.",
                    "Sempre combine 'SameSite=None' obrigatoriamente com a flag 'Secure'."
            ));
        }
    }
}