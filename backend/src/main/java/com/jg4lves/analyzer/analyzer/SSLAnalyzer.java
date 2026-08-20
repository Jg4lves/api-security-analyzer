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
                            "Certificado SSL/TLS inválido ou expirado.",
                            "Conexões não criptografadas ou com certificados inválidos impedem o canal seguro de comunicação, expondo todo o tráfego a interceptações (Man-in-the-Middle) e alertas de bloqueio nos navegadores dos usuários.",
                            "Renove o certificado SSL/TLS junto a uma Autoridade Certificadora (CA) válida (como Let's Encrypt, DigiCert, etc.) e verifique as datas de expiração no servidor."
                    )
            );
        }
    }
}