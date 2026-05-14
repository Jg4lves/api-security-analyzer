package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Component
public class SecurityTxtAnalyzer {

    private final HttpClient httpClient;

    public SecurityTxtAnalyzer(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void analyze(
            String baseUrl,
            SecurityReport report
    ) {

        try {

            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(
                                    URI.create(
                                            baseUrl +
                                                    "/.well-known/security.txt"
                                    )
                            )
                            .GET()
                            .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if(response.statusCode() != 200) {

                report.addIssue(
                        new SecurityIssue(
                                "LOW",
                                "security.txt file not found"
                        )
                );
            }

        } catch (Exception e) {

            report.addIssue(
                    new SecurityIssue(
                            "LOW",
                            "Unable to verify security.txt"
                    )
            );
        }
    }
}