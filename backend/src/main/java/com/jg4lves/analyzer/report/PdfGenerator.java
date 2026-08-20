package com.jg4lves.analyzer.report;

import com.jg4lves.analyzer.model.SecurityIssue;
import com.jg4lves.analyzer.model.SecurityReport;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfWriter;

import java.io.ByteArrayOutputStream;

public class PdfGenerator {

    public byte[] generate(SecurityReport report) {

        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Document document = new Document();

            PdfWriter.getInstance(document, output);

            document.open();

            document.add(new Paragraph("Security Analysis Report"));
            document.add(new Paragraph("Target: " + report.getUrl()));
            document.add(new Paragraph("Risk Score: " + report.getScore()));

            document.add(Chunk.NEWLINE);

            for (SecurityIssue issue : report.getIssues()) {

                document.add(new Paragraph("Severity: " + issue.getSeverity()));

                // Agora puxa direto da própria issue!
                document.add(new Paragraph("Description: " + issue.getDescription()));
                document.add(new Paragraph("Impact: " + issue.getImpact()));
                document.add(new Paragraph("Recommendation: " + issue.getRecommendation()));

                document.add(Chunk.NEWLINE);
            }

            document.close();

            return output.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}