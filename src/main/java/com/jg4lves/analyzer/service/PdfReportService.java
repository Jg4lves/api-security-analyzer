package com.jg4lves.analyzer.service;

import com.jg4lves.analyzer.model.SecurityReport;
import com.jg4lves.analyzer.report.PdfGenerator;
import org.springframework.stereotype.Service;

@Service
public class PdfReportService {

    private final PdfGenerator pdfGenerator =
            new PdfGenerator();

    public byte[] generate(
            SecurityReport report
    ) {

        return pdfGenerator.generate(report);
    }
}