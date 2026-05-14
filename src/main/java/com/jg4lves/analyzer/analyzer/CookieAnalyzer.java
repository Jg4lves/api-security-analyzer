package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class CookieAnalyzer {

    public void analyze(
            HttpHeaders headers,
            SecurityReport report
    ) {

        boolean missingHttpOnly = false;
        boolean missingSecure = false;
        boolean missingSameSite = false;

        for (String cookie : headers.allValues("Set-Cookie")) {

            if (!cookie.contains("HttpOnly")) {
                missingHttpOnly = true;
            }

            if (!cookie.contains("Secure")) {
                missingSecure = true;
            }

            if (!cookie.contains("SameSite")) {
                missingSameSite = true;
            }
        }

        if (missingHttpOnly) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Cookie without HttpOnly flag"
                    )
            );
        }

        if (missingSecure) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Cookie without Secure flag"
                    )
            );
        }

        if (missingSameSite) {

            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Cookie without SameSite attribute"
                    )
            );
        }
    }
}