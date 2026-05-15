package com.jg4lves.analyzer.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityReport {
    private String url;
    private int score;
    private List<SecurityIssue> issues = new ArrayList<>();

    public void addIssue(SecurityIssue issue) {
        issues.add(issue);
    }
}
