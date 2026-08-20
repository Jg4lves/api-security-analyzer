package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Component
public class SSLAnalyzer {

    public void analyze(SSLSession session, SecurityReport report) {

        try {
            for (Certificate rawCert : session.getPeerCertificates()) {

                X509Certificate cert = (X509Certificate) rawCert;

                cert.checkValidity();

                Date expirationDate = cert.getNotAfter();
                Instant now = Instant.now();
                Instant expirationInstant = expirationDate.toInstant();

                long daysUntilExpiration = ChronoUnit.DAYS.between(now, expirationInstant);

                if (daysUntilExpiration >= 0 && daysUntilExpiration <= 15) {
                    report.addIssue(
                            new SecurityIssue(
                                    "MEDIUM",
                                    "O certificado SSL/TLS está prestes a expirar (vence em " + daysUntilExpiration + " dias).",
                                    "Se o certificado expirar, os navegadores bloquearão o acesso dos usuários com uma tela de aviso de segurança, causando indisponibilidade total do serviço (Downtime).",
                                    "Providencie a renovação do certificado imediatamente e atualize as configurações no servidor web ou Load Balancer."
                            )
                    );
                }
            }

        } catch (Exception e) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Certificado SSL/TLS inválido ou expirado detectado na cadeia de confiança.",
                            "Conexões não criptografadas ou com certificados inválidos impedem o canal seguro de comunicação, expondo o tráfego a interceptações (Man-in-the-Middle).",
                            "Renove o certificado SSL/TLS (incluindo possíveis intermediários) junto a uma Autoridade Certificadora válida."
                    )
            );
        }
    }
}