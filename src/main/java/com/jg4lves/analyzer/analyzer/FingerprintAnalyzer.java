package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class FingerprintAnalyzer {

    public void analyze(
            HttpHeaders headers,
            SecurityReport report
    ) {

        headers.firstValue("Server")
                .ifPresent(server -> {

                    report.addIssue(
                            new SecurityIssue(
                                    "LOW",
                                    "Server fingerprint exposed: " + server
                            )
                    );
                });

        headers.firstValue("X-Powered-By")
                .ifPresent(powered -> {

                    report.addIssue(
                            new SecurityIssue(
                                    "LOW",
                                    "Technology exposure detected: " + powered
                            )
                    );
                });
    }
}