package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;

@Component
public class SSLAnalyzer {

    public void analyze(SSLSession session, SecurityReport report) {

        try {

            X509Certificate cert =
                    (X509Certificate) session.getPeerCertificates()[0];

            cert.checkValidity();

        } catch (Exception e) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Invalid or expired SSL certificate"
                    )
            );
        }
    }
}