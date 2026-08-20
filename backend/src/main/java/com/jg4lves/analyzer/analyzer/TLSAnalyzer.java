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

        if (protocol.equals("TLSv1") || protocol.equals("TLSv1.1") || protocol.equals("SSLv3")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "Versão obsoleta do protocolo TLS/SSL detectada: " + protocol,
                            "Versões antigas do protocolo TLS possuem vulnerabilidades conhecidas (como BEAST e POODLE) e não atendem aos padrões modernos de segurança da Web.",
                            "Desabilite o suporte a SSLv3, TLS 1.0 e TLS 1.1 no servidor e force o uso exclusivo de TLS 1.2 ou TLS 1.3."
                    )
            );
        }

        String cipher = session.getCipherSuite();

        if (cipher.contains("RC4") || cipher.contains("DES") || cipher.contains("3DES") || cipher.contains("NULL") || cipher.contains("anon")) {

            report.addIssue(
                    new SecurityIssue(
                            "CRITICAL",
                            "Algoritmo de criptografia (Cipher Suite) fraco detectado: " + cipher,
                            "Ciphers antigos ou sem cifragem podem permitir a descriptografia do tráfego em tempo hábil por atacantes (ex: vulnerabilidade SWEET32 com 3DES).",
                            "Reconfigure as suítes de criptografia do servidor para permitir apenas ciphers seguros com Forward Secrecy (como AES-GCM e ChaCha20-Poly1305)."
                    )
            );
        }
    }
}