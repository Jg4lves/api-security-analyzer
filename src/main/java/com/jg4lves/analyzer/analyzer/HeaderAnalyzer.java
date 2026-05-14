package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class HeaderAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {

        if (headers.firstValue("Content-Security-Policy").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Missing Content-Security-Policy header"
                    )
            );
        }

        if (headers.firstValue("Strict-Transport-Security").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Missing HSTS header"
                    )
            );
        }

        if (headers.firstValue("X-Frame-Options").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "MEDIUM",
                            "Missing X-Frame-Options header"
                    )
            );
        }

        if (headers.firstValue("X-Content-Type-Options").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Missing X-Content-Type-Options header"
                    )
            );
        }

        if (headers.firstValue("Referrer-Policy").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Missing Referrer-Policy header"
                    )
            );
        }

        if (headers.firstValue("Permissions-Policy").isEmpty()) {

            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Missing Permissions-Policy header"
                    )
            );
        }
    }
}