package com.jg4lves.analyzer.report;

import com.jg4lves.analyzer.knowledgebase.VulnerabilityKnowledgeBase;
import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import com.jg4lves.analyzer.model.VulnerabilityInfo;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfWriter;

import java.io.ByteArrayOutputStream;

public class PdfGenerator {

    public byte[] generate(
            SecurityReport report
    ) {

        try {

            ByteArrayOutputStream output =
                    new ByteArrayOutputStream();

            Document document = new Document();

            PdfWriter.getInstance(
                    document,
                    output
            );

            document.open();

            document.add(
                    new Paragraph(
                            "Security Analysis Report"
                    )
            );

            document.add(
                    new Paragraph(
                            "Target: " + report.getUrl()
                    )
            );

            document.add(
                    new Paragraph(
                            "Risk Score: " + report.getScore()
                    )
            );

            document.add(Chunk.NEWLINE);

            for (SecurityIssue issue : report.getIssues()) {

                document.add(
                        new Paragraph(
                                "Issue: " + issue.getMessage()
                        )
                );

                document.add(
                        new Paragraph(
                                "Severity: " + issue.getSeverity()
                        )
                );

                VulnerabilityInfo info =
                        VulnerabilityKnowledgeBase
                                .getInfo(issue.getMessage());

                document.add(
                        new Paragraph(
                                "Description: "
                                        + info.getDescription()
                        )
                );

                document.add(
                        new Paragraph(
                                "Impact: "
                                        + info.getImpact()
                        )
                );

                document.add(
                        new Paragraph(
                                "Recommendation: "
                                        + info.getRecommendation()
                        )
                );

                document.add(Chunk.NEWLINE);
            }

            document.close();

            return output.toByteArray();

        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }
}