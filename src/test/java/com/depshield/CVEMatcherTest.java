package com.depshield;

import com.depshield.model.Dependency;
import com.depshield.model.RiskReport;
import com.depshield.scanner.CVEMatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CVEMatcherTest {

    private CVEMatcher matcher;

    @BeforeEach
    void setUp() {
        // Point to the real registry
        matcher = new CVEMatcher("data/cve-registry.json");
    }

    @Test
    void shouldDetectLog4ShellAsCritical() {
        Dependency dep = new Dependency(
                "org.apache.logging.log4j", "log4j-core", "2.14.1");

        RiskReport report = matcher.match(dep);

        assertTrue(report.isVulnerable());
        assertEquals("CRITICAL", report.getSeverity());
        assertEquals("CVE-2021-44228", report.getCveEntry().getCveId());
    }

    @Test
    void shouldReturnSafeForCleanDependency() {
        Dependency dep = new Dependency(
                "com.fasterxml.jackson.core", "jackson-databind", "2.15.2");

        RiskReport report = matcher.match(dep);

        assertFalse(report.isVulnerable());
        assertEquals("SAFE", report.getSeverity());
    }

    @Test
    void shouldReturnSafeForDifferentVersion() {
        // log4j-core 2.17.1 is the patched version — should be SAFE
        Dependency dep = new Dependency(
                "org.apache.logging.log4j", "log4j-core", "2.17.1");

        RiskReport report = matcher.match(dep);

        assertFalse(report.isVulnerable());
        assertEquals("SAFE", report.getSeverity());
    }

    @Test
    void shouldDetectGsonAsHigh() {
        Dependency dep = new Dependency(
                "com.google.code.gson", "gson", "2.8.9");

        RiskReport report = matcher.match(dep);

        assertTrue(report.isVulnerable());
        assertEquals("HIGH", report.getSeverity());
    }
}