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

        String protocol = session.getProtocol().toUpperCase();

        if (protocol.startsWith("SSL") || protocol.equals("TLSV1") || protocol.equals("TLSV1.1")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Versão obsoleta do protocolo TLS/SSL detectada: " + protocol,
                            "Versões antigas do protocolo TLS possuem vulnerabilidades conhecidas (como BEAST e POODLE) e não atendem aos padrões modernos de segurança da Web.",
                            "Desabilite o suporte a " + protocol + " no servidor e force o uso exclusivo de TLS 1.2 ou TLS 1.3."
                    )
            );
        }

        String cipher = session.getCipherSuite().toUpperCase();

        if (cipher.contains("RC4") ||
                cipher.contains("DES") ||
                cipher.contains("NULL") ||
                cipher.contains("ANON") ||
                cipher.contains("EXPORT") ||
                cipher.contains("MD5")) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Algoritmo de criptografia (Cipher Suite) fraco detectado: " + cipher,
                            "Ciphers antigos, anônimos, de exportação (FREAK) ou sem cifragem permitem a quebra e descriptografia do tráfego por atacantes.",
                            "Reconfigure as suítes de criptografia do servidor para permitir apenas ciphers seguros com Forward Secrecy (como AES-GCM e ChaCha20-Poly1305)."
                    )
            );
        }
    }
}