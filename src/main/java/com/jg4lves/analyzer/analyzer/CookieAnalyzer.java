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

        headers.allValues("Set-Cookie")
                .forEach(cookie -> {

                    if(!cookie.contains("HttpOnly")) {

                        report.addIssue(
                                new SecurityIssue(
                                        "HIGH",
                                        "Cookie without HttpOnly flag"
                                )
                        );
                    }

                    if(!cookie.contains("Secure")) {

                        report.addIssue(
                                new SecurityIssue(
                                        "HIGH",
                                        "Cookie without Secure flag"
                                )
                        );
                    }

                    if(!cookie.contains("SameSite")) {

                        report.addIssue(
                                new SecurityIssue(
                                        "MEDIUM",
                                        "Cookie without SameSite attribute"
                                )
                        );
                    }
                });
    }
}