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

        // Agora o Set guarda uma assinatura única baseada na Recomendação (que é estática)
        Set<String> punishedIssues = new HashSet<>();

        for (SecurityIssue issue : report.getIssues()) {

            if (issue.getSeverity() == null) {
                continue;
            }

            String issueSignature = issue.getSeverity().toUpperCase() + "-" + issue.getRecommendation();

            if (punishedIssues.contains(issueSignature)) {
                continue;
            }

            switch (issue.getSeverity().toUpperCase()) {
                case "CRITICAL" -> score -= 25;
                case "HIGH" -> score -= 10;
                case "MEDIUM" -> score -= 3;
                case "LOW" -> score -= 1;
                default -> score -= 1;
            }

            punishedIssues.add(issueSignature);
        }

        return Math.max(score, 0);
    }
}