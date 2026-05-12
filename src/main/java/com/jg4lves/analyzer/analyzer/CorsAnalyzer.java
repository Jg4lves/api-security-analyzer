package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;

@Component
public class CorsAnalyzer {

    public void analyze(HttpHeaders headers, SecurityReport report) {

        String cors = headers
                .firstValue("Access-Control-Allow-Origin")
                .orElse("");

        if(cors.equals("*")) {

            report.addIssue(
                    new SecurityIssue(
                            "HIGH",
                            "CORS configured with wildcard (*)"
                    )
            );
        }
    }
}
