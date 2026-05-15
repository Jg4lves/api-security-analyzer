package com.jg4lves.analyzer.controller;

import com.jg4lves.analyzer.model.ScanRequest;
import com.jg4lves.analyzer.model.SecurityReport;
import com.jg4lves.analyzer.service.SecurityScanService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/security")
public class ScanController {

    private final SecurityScanService service;

    public ScanController(SecurityScanService service) {
        this.service = service;
    }

    @PostMapping("/scan")
    public SecurityReport scan(
            @RequestBody ScanRequest request
    ) {

        return service.scan(request.getUrl());
    }
}