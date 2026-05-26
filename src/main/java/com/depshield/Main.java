/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.depshield;

import com.depshield.gate.BuildGate;
import com.depshield.model.Dependency;
import com.depshield.model.RiskReport;
import com.depshield.parser.PomParser;
import com.depshield.scanner.CVEMatcher;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        // Default paths — can be overridden via command line args
        String pomPath      = "pom.xml";
        String registryPath = "data/cve-registry.json";

        // Allow paths to be passed as arguments
        // Usage: java -jar depshield.jar <pom-path> <registry-path>
        if (args.length >= 2) {
            pomPath      = args[0];
            registryPath = args[1];
        }

        // Generate a build ID from current timestamp
        String buildId = "BUILD-" + LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));

        System.out.println("========================================");
        System.out.println(" DepShield - Dependency Vulnerability Scanner");
        System.out.println(" Build ID : " + buildId);
        System.out.println("========================================\n");

        // Step 1: Parse pom.xml
        System.out.println("[1/3] Parsing pom.xml: " + pomPath);
        PomParser parser = new PomParser();
        List<Dependency> dependencies = parser.parse(pomPath);

        if (dependencies.isEmpty()) {
            System.out.println("[DepShield] No dependencies found. Exiting.");
            System.exit(0);
        }
        System.out.println("      Found " + dependencies.size() + " dependencies.\n");

        // Step 2: Match against CVE registry
        System.out.println("[2/3] Scanning against CVE registry: " + registryPath);
        CVEMatcher matcher = new CVEMatcher(registryPath);
        List<RiskReport> reports = matcher.matchAll(dependencies);
        System.out.println("      Scan complete.\n");

        // Step 3: Evaluate through build gate
        System.out.println("[3/3] Evaluating build gate policy...\n");
        BuildGate gate = new BuildGate();
        boolean passed = gate.evaluate(reports, buildId);

        // Exit code drives Jenkins pipeline decision
        if (!passed) {
            System.out.println("[DepShield] BUILD BLOCKED. Fix vulnerable dependencies.");
            System.exit(1); // Jenkins sees this as stage failure
        }

        System.out.println("[DepShield] BUILD PASSED. No critical vulnerabilities found.");
        System.exit(0);
    }
}
