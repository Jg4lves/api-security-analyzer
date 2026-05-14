package com.jg4lves.analyzer.service;

import com.jg4lves.analyzer.analyzer.CorsAnalyzer;
import com.jg4lves.analyzer.analyzer.HeaderAnalyzer;
import com.jg4lves.analyzer.analyzer.SSLAnalyzer;
import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
public class SecurityScanService {

    private final HttpClient httpClient;
    private final HeaderAnalyzer headerAnalyzer;
    private final CorsAnalyzer corsAnalyzer;
    private final SSLAnalyzer sslAnalyzer;

    public SecurityScanService(
            HttpClient httpClient,
            HeaderAnalyzer headerAnalyzer,
            CorsAnalyzer corsAnalyzer,
            SSLAnalyzer sslAnalyzer
    ) {
        this.httpClient = httpClient;
        this.headerAnalyzer = headerAnalyzer;
        this.corsAnalyzer = corsAnalyzer;
        this.sslAnalyzer = sslAnalyzer;
    }

    public SecurityReport scan(String url) {

        SecurityReport report = new SecurityReport();
        report.setUrl(url);

        try {

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            headerAnalyzer.analyze(response.headers(), report);

            corsAnalyzer.analyze(response.headers(), report);

            response.sslSession().ifPresent(
                    ssl -> sslAnalyzer.analyze(ssl, report)
            );

            int score = 100 - (report.getIssues().size() * 15);

            report.setScore(Math.max(score, 0));

        } catch (Exception e) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Failed to scan target"
                    )
            );

            report.setScore(0);
        }

        return report;
    }
}