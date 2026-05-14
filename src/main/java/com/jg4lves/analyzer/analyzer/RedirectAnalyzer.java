package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpResponse;

@Component
public class RedirectAnalyzer {

    public void analyze(
            HttpResponse<?> response,
            SecurityReport report
    ) {

        int status = response.statusCode();

        if(status == 301 || status == 302) {

            String location =
                    response.headers()
                            .firstValue("Location")
                            .orElse("");

            if(location.startsWith("http://")) {

                report.addIssue(
                        new SecurityIssue(
                                "MEDIUM",
                                "Redirecting to insecure HTTP endpoint"
                        )
                );
            }
        }
    }
}