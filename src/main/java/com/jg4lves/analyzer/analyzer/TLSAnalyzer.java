package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSession;

@Component
public class TLSAnalyzer {

    public void analyze(
            SSLSession session,
            SecurityReport report
    ) {

        String protocol = session.getProtocol();

        if(protocol.contains("TLSv1")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Deprecated TLS version detected: " + protocol
                    )
            );
        }

        String cipher = session.getCipherSuite();

        if(cipher.contains("RC4")
                || cipher.contains("DES")) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Weak cipher suite detected: " + cipher
                    )
            );
        }
    }
}