package com.jg4lves.analyzer.controller;

import com.jg4lves.analyzer.model.SecurityReport;
import com.jg4lves.analyzer.model.ScanRequest;
import com.jg4lves.analyzer.service.PdfReportService;
import com.jg4lves.analyzer.service.SecurityScanService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/security")
public class ReportController {

    private final SecurityScanService scanService;
    private final PdfReportService pdfService;

    public ReportController(
            SecurityScanService scanService,
            PdfReportService pdfService
    ) {
        this.scanService = scanService;
        this.pdfService = pdfService;
    }

    @PostMapping("/report")
    public ResponseEntity<byte[]> generateReport(
            @RequestBody ScanRequest request
    ) {

        SecurityReport report =
                scanService.scan(
                        request.getUrl()
                );

        byte[] pdf =
                pdfService.generate(report);

        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=report.pdf"
                )
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}