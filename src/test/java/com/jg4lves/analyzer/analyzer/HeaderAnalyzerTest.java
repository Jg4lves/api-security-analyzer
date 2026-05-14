package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HeaderAnalyzerTest {

    private final HeaderAnalyzer analyzer =
            new HeaderAnalyzer();

    @Test
    void shouldDetectMissingCSP() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("Content-Security-Policy"))
        );
    }

    @Test
    void shouldDetectMissingHSTS() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Content-Security-Policy",
                        List.of("default-src 'self'")
                ),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("HSTS"))
        );
    }

    @Test
    void shouldPassWhenHeadersAreSecure() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Content-Security-Policy",
                        List.of("default-src 'self'"),
                        "Strict-Transport-Security",
                        List.of("max-age=31536000")
                ),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertEquals(0, report.getIssues().size());
    }
}