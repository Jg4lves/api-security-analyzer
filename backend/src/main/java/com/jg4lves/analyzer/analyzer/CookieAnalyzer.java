package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.HttpCookie;
import java.net.http.HttpHeaders;
import java.util.List;

@Component
public class CookieAnalyzer {

    private static final List<String> SENSITIVE_COOKIES = List.of(
            "jsessionid", "phpsessid", "session_id", "auth", "token", "jwt", "bearer"
    );

    public void analyze(HttpHeaders headers, SecurityReport report) {
        List<String> setCookieHeaders = headers.allValues("Set-Cookie");

        for (String headerValue : setCookieHeaders) {
            try {
                List<HttpCookie> cookies = HttpCookie.parse(headerValue);
                for (HttpCookie cookie : cookies) {
                    analyzeIndividualCookie(cookie, headerValue, report);
                }
            } catch (IllegalArgumentException e) {
            }
        }
    }

    private void analyzeIndividualCookie(HttpCookie cookie, String rawHeader, SecurityReport report) {
        String cookieName = cookie.getName();

        if (!isSensitiveCookie(cookieName)) {
            return;
        }

        if (!cookie.isHttpOnly()) {
            report.addIssue(new SecurityIssue(
                    "HIGH",
                    String.format("Cookie de sessão '%s' está sem a flag 'HttpOnly'.", cookieName),
                    "Permite roubo de sessão via ataques de Cross-Site Scripting (XSS).",
                    "Adicione o atributo 'HttpOnly' na diretiva do cookie."
            ));
        }

        if (!cookie.getSecure()) {
            report.addIssue(new SecurityIssue(
                    "HIGH",
                    String.format("Cookie de sessão '%s' está sem a flag 'Secure'.", cookieName),
                    "Permite a interceptação do cookie em tráfego de redes HTTP não criptografadas.",
                    "Adicione a flag 'Secure' para garantir que o cookie trafegue apenas via HTTPS."
            ));
        }

        String rawHeaderLowerCase = rawHeader.toLowerCase();
        boolean hasSameSite = rawHeaderLowerCase.contains("samesite=");

        if (!hasSameSite) {
            report.addIssue(new SecurityIssue(
                    "MEDIUM",
                    String.format("Cookie de sessão '%s' não define o atributo 'SameSite'.", cookieName),
                    "A ausência do SameSite deixa a aplicação mais vulnerável a ataques de Cross-Site Request Forgery (CSRF).",
                    "Configure o atributo 'SameSite=Lax' ou 'SameSite=Strict' no cookie."
            ));
        }
    }

    private boolean isSensitiveCookie(String cookieName) {
        String nameLower = cookieName.toLowerCase();

        if (nameLower.startsWith("__secure-") || nameLower.startsWith("__host-")) {
            return true;
        }

        for (String sensitive : SENSITIVE_COOKIES) {
            if (nameLower.contains(sensitive)) {
                return true;
            }
        }

        return false;
    }
}