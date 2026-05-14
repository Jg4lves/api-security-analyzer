package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

@Component
public class RiskScoreCalculator {

    public int calculate(SecurityReport report) {

        int score = 100;

        for(SecurityIssue issue : report.getIssues()) {

            switch (issue.getSeverity()) {

                case "LOW" -> score -= 5;

                case "MEDIUM" -> score -= 10;

                case "HIGH" -> score -= 20;

                case "CRITICAL" -> score -= 35;
            }
        }

        return Math.max(score, 0);
    }
}