package com.jg4lves.analyzer.service;

import com.jg4lves.analyzer.analyzer.*;
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
    private final CookieAnalyzer cookieAnalyzer;
    private final TLSAnalyzer tlsAnalyzer;
    private final FingerprintAnalyzer fingerprintAnalyzer;
    private final RedirectAnalyzer redirectAnalyzer;
    private final SecurityTxtAnalyzer securityTxtAnalyzer;
    private final RiskScoreCalculator riskScoreCalculator;

    public SecurityScanService(
            HttpClient httpClient,
            HeaderAnalyzer headerAnalyzer,
            CorsAnalyzer corsAnalyzer,
            SSLAnalyzer sslAnalyzer, CookieAnalyzer cookieAnalyzer, TLSAnalyzer tlsAnalyzer, FingerprintAnalyzer fingerprintAnalyzer, RedirectAnalyzer redirectAnalyzer, SecurityTxtAnalyzer securityTxtAnalyzer, RiskScoreCalculator riskScoreCalculator
    ) {
        this.httpClient = httpClient;
        this.headerAnalyzer = headerAnalyzer;
        this.corsAnalyzer = corsAnalyzer;
        this.sslAnalyzer = sslAnalyzer;
        this.cookieAnalyzer = cookieAnalyzer;
        this.tlsAnalyzer = tlsAnalyzer;
        this.fingerprintAnalyzer = fingerprintAnalyzer;
        this.redirectAnalyzer = redirectAnalyzer;
        this.securityTxtAnalyzer = securityTxtAnalyzer;
        this.riskScoreCalculator = riskScoreCalculator;
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

            cookieAnalyzer.analyze(response.headers(), report);

            fingerprintAnalyzer.analyze(response.headers(), report);

            redirectAnalyzer.analyze(response, report);

            securityTxtAnalyzer.analyze(url, report);

            response.sslSession().ifPresent(ssl -> {

                sslAnalyzer.analyze(ssl, report);

                tlsAnalyzer.analyze(ssl, report);
            });

            report.setScore(
                    riskScoreCalculator.calculate(report)
            );

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