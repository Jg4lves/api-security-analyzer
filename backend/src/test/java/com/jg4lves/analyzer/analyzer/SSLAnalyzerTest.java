package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityReport;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SSLAnalyzerTest {

    private final SSLAnalyzer analyzer =
            new SSLAnalyzer();

    @Test
    void shouldDetectInvalidCertificate() {

        SSLSession session = mock(SSLSession.class);

        SecurityReport report = new SecurityReport();

        analyzer.analyze(session, report);

        assertFalse(report.getIssues().isEmpty());
    }
}