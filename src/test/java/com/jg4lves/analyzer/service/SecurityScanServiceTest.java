package com.jg4lves.analyzer.service;

import com.jg4lves.analyzer.analyzer.CorsAnalyzer;
import com.jg4lves.analyzer.analyzer.HeaderAnalyzer;
import com.jg4lves.analyzer.analyzer.SSLAnalyzer;
import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SecurityScanServiceTest {

    @Mock
    private HttpClient httpClient;

    @Mock
    private HeaderAnalyzer headerAnalyzer;

    @Mock
    private CorsAnalyzer corsAnalyzer;

    @Mock
    private SSLAnalyzer sslAnalyzer;

    @Mock
    private HttpResponse<String> response;

    private SecurityScanService service;

    @BeforeEach
    void setup() {

        MockitoAnnotations.openMocks(this);

        service = new SecurityScanService(
                httpClient,
                headerAnalyzer,
                corsAnalyzer,
                sslAnalyzer
        );
    }

    @Test
    void shouldGenerateSecurityReport() throws Exception {

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Content-Type",
                        java.util.List.of("text/html")
                ),
                (a, b) -> true
        );

        when(response.headers()).thenReturn(headers);

        when(response.sslSession())
                .thenReturn(Optional.empty());

        when(httpClient.send(
                any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)
        )).thenReturn(response);

        SecurityReport report =
                service.scan("https://example.com");

        assertNotNull(report);

        assertEquals("https://example.com", report.getUrl());

        verify(headerAnalyzer, times(1))
                .analyze(any(), any());

        verify(corsAnalyzer, times(1))
                .analyze(any(), any());
    }

    @Test
    void shouldReturnScoreZeroWhenRequestFails() throws Exception {

        when(httpClient.send(
                any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)
        )).thenThrow(new RuntimeException());

        SecurityReport report =
                service.scan("https://invalid-url.com");

        assertEquals(0, report.getScore());

        assertFalse(report.getIssues().isEmpty());
    }
}