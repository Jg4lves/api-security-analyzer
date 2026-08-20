package com.jg4lves.analyzer.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityIssue {
    private String severity;
    private String description;
    private String impact;
    private String recommendation;
}