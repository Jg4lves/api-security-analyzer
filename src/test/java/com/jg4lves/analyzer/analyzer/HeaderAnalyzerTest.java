package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HeaderAnalyzerTest {

    private final HeaderAnalyzer analyzer = new HeaderAnalyzer();

    @Test
    void shouldDetectMissingCspHeader() {

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
    void shouldDetectMissingHstsHeader() {

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
    void shouldDetectMissingXFrameOptionsHeader() {

        HttpHeaders headers = createSecureHeadersWithout(
                "X-Frame-Options"
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("X-Frame-Options"))
        );
    }

    @Test
    void shouldDetectMissingXContentTypeOptionsHeader() {

        HttpHeaders headers = createSecureHeadersWithout(
                "X-Content-Type-Options"
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("X-Content-Type-Options"))
        );
    }

    @Test
    void shouldDetectMissingReferrerPolicyHeader() {

        HttpHeaders headers = createSecureHeadersWithout(
                "Referrer-Policy"
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("Referrer-Policy"))
        );
    }

    @Test
    void shouldDetectMissingPermissionsPolicyHeader() {

        HttpHeaders headers = createSecureHeadersWithout(
                "Permissions-Policy"
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(
                report.getIssues()
                        .stream()
                        .anyMatch(issue ->
                                issue.getMessage()
                                        .contains("Permissions-Policy"))
        );
    }

    @Test
    void shouldPassWhenAllSecurityHeadersArePresent() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Content-Security-Policy",
                        List.of("default-src 'self'"),

                        "Strict-Transport-Security",
                        List.of("max-age=31536000"),

                        "X-Frame-Options",
                        List.of("DENY"),

                        "X-Content-Type-Options",
                        List.of("nosniff"),

                        "Referrer-Policy",
                        List.of("strict-origin"),

                        "Permissions-Policy",
                        List.of("geolocation=()")
                ),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertTrue(report.getIssues().isEmpty());
    }

    private HttpHeaders createSecureHeadersWithout(String headerToRemove) {

        Map<String, List<String>> headers = new java.util.HashMap<>();

        headers.put(
                "Content-Security-Policy",
                List.of("default-src 'self'")
        );

        headers.put(
                "Strict-Transport-Security",
                List.of("max-age=31536000")
        );

        headers.put(
                "X-Frame-Options",
                List.of("DENY")
        );

        headers.put(
                "X-Content-Type-Options",
                List.of("nosniff")
        );

        headers.put(
                "Referrer-Policy",
                List.of("strict-origin")
        );

        headers.put(
                "Permissions-Policy",
                List.of("geolocation=()")
        );

        headers.remove(headerToRemove);

        return HttpHeaders.of(headers, (a, b) -> true);
    }
}