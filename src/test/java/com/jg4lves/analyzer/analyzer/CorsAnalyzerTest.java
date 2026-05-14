package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CorsAnalyzerTest {

    private final CorsAnalyzer analyzer =
            new CorsAnalyzer();

    @Test
    void shouldDetectWildcardCors() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Access-Control-Allow-Origin",
                        List.of("*")
                ),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertEquals(1, report.getIssues().size());
    }

    @Test
    void shouldPassSecureCors() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Access-Control-Allow-Origin",
                        List.of("https://myapp.com")
                ),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertEquals(0, report.getIssues().size());
    }

    @Test
    void shouldPassWhenCorsHeaderMissing() {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(),
                (a, b) -> true
        );

        SecurityReport report = new SecurityReport();

        analyzer.analyze(headers, report);

        assertEquals(0, report.getIssues().size());
    }
}