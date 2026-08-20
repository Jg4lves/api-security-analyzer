package com.jg4lves.analyzer.analyzer;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class RiskScoreCalculator {

    public int calculate(SecurityReport report) {

        int score = 100;
        // Usa um Set para guardar as descrições e não punir o mesmo erro duas vezes
        Set<String> punishedIssues = new HashSet<>();

        for (SecurityIssue issue : report.getIssues()) {

            if (issue.getSeverity() == null || punishedIssues.contains(issue.getDescription())) {
                continue;
            }

            switch (issue.getSeverity().toUpperCase()) {
                case "LOW" -> score -= 2;
                case "MEDIUM" -> score -= 5;
                case "HIGH" -> score -= 10;
                case "CRITICAL" -> score -= 20;
                default -> score -= 1;
            }

            punishedIssues.add(issue.getDescription());
        }

        return Math.max(score, 0);
    }
}