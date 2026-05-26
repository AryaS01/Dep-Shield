package com.depshield.scanner;

import com.depshield.model.CVEEntry;
import com.depshield.model.Dependency;
import com.depshield.model.RiskReport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class CVEMatcher {

    private List<CVEEntry> cveRegistry;

    public CVEMatcher(String registryPath) {
        this.cveRegistry = loadRegistry(registryPath);
    }

    // Load the JSON registry once at construction time
    private List<CVEEntry> loadRegistry(String registryPath) {
        List<CVEEntry> entries = new ArrayList<>();
        try {
            ObjectMapper mapper = new ObjectMapper();

            // Read the root JSON node
            JsonNode root = mapper.readTree(new File(registryPath));

            // Navigate to the "cves" array
            JsonNode cvesArray = root.get("cves");

            // Convert each element to a CVEEntry object
            for (JsonNode node : cvesArray) {
                CVEEntry entry = mapper.treeToValue(node, CVEEntry.class);
                entries.add(entry);
            }

            System.out.println("[DepShield] Loaded " + entries.size() 
                             + " CVE entries from registry.");

        } catch (Exception e) {
            System.err.println("[DepShield] Failed to load CVE registry: " 
                             + e.getMessage());
        }
        return entries;
    }

    // Match a single dependency against the registry
    public RiskReport match(Dependency dependency) {
        for (CVEEntry cve : cveRegistry) {
            if (cve.getGroupId().equals(dependency.getGroupId()) &&
                cve.getArtifactId().equals(dependency.getArtifactId()) &&
                cve.getAffectedVersion().equals(dependency.getVersion())) {

                // Match found — return a vulnerable report
                return new RiskReport(dependency, cve, cve.getSeverity(), true);
            }
        }

        // No match — dependency is safe
        return new RiskReport(dependency, null, "SAFE", false);
    }

    // Match a full list of dependencies
    public List<RiskReport> matchAll(List<Dependency> dependencies) {
        List<RiskReport> reports = new ArrayList<>();
        for (Dependency dep : dependencies) {
            reports.add(match(dep));
        }
        return reports;
    }
}