package com.jg4lves.analyzer.service;

import com.jg4lves.analyzer.analyzer.CookieAnalyzer;
import com.jg4lves.analyzer.analyzer.CorsAnalyzer;
import com.jg4lves.analyzer.analyzer.FingerprintAnalyzer;
import com.jg4lves.analyzer.analyzer.HeaderAnalyzer;
import com.jg4lves.analyzer.analyzer.RedirectAnalyzer;
import com.jg4lves.analyzer.analyzer.RiskScoreCalculator;
import com.jg4lves.analyzer.analyzer.SSLAnalyzer;
import com.jg4lves.analyzer.analyzer.SecurityTxtAnalyzer;
import com.jg4lves.analyzer.analyzer.TLSAnalyzer;
import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
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
    private CookieAnalyzer cookieAnalyzer;

    @Mock
    private TLSAnalyzer tlsAnalyzer;

    @Mock
    private FingerprintAnalyzer fingerprintAnalyzer;

    @Mock
    private RedirectAnalyzer redirectAnalyzer;

    @Mock
    private SecurityTxtAnalyzer securityTxtAnalyzer;

    @Mock
    private RiskScoreCalculator riskScoreCalculator;

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
                sslAnalyzer,
                cookieAnalyzer,
                tlsAnalyzer,
                fingerprintAnalyzer,
                redirectAnalyzer,
                securityTxtAnalyzer,
                riskScoreCalculator
        );
    }

    @Test
    void shouldGenerateSecurityReport() throws Exception {

        HttpHeaders headers = HttpHeaders.of(
                Map.of("Content-Type", List.of("text/html")),
                (a, b) -> true
        );

        when(response.headers()).thenReturn(headers);
        when(response.sslSession()).thenReturn(Optional.empty());

        when(httpClient.send(
                any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)
        )).thenReturn(response);

        when(riskScoreCalculator.calculate(any())).thenReturn(85);

        SecurityReport report = service.scan("https://example.com");

        assertAll(
                () -> assertNotNull(report),
                () -> assertEquals("https://example.com", report.getUrl()),
                () -> assertEquals(85, report.getScore())
        );

        verify(headerAnalyzer).analyze(any(), any());
        verify(corsAnalyzer).analyze(any(), any());
        verify(cookieAnalyzer).analyze(any(), any());
        verify(fingerprintAnalyzer).analyze(any(), any());
        verify(redirectAnalyzer).analyze(any(), any());
        verify(securityTxtAnalyzer).analyze(any(), any());
        verify(riskScoreCalculator).calculate(any());
    }

    @Test
    void shouldReturnScoreZeroWhenRequestFails() throws Exception {

        when(httpClient.send(
                any(HttpRequest.class),
                any(HttpResponse.BodyHandler.class)
        )).thenThrow(new RuntimeException());

        SecurityReport report = service.scan("https://invalid-url.com");

        assertAll(
                () -> assertEquals(0, report.getScore()),
                () -> assertFalse(report.getIssues().isEmpty())
        );
    }
}