package com.depshield.model;

public class RiskReport {
    private Dependency dependency;
    private CVEEntry cveEntry;       // null if no vulnerability found
    private String severity;         // SAFE if no CVE found
    private boolean vulnerable;

    public RiskReport(Dependency dependency, CVEEntry cveEntry, 
                      String severity, boolean vulnerable) {
        this.dependency = dependency;
        this.cveEntry = cveEntry;
        this.severity = severity;
        this.vulnerable = vulnerable;
    }

    public Dependency getDependency() { return dependency; }
    public CVEEntry getCveEntry() { return cveEntry; }
    public String getSeverity() { return severity; }
    public boolean isVulnerable() { return vulnerable; }

    @Override
    public String toString() {
        if (!vulnerable) {
            return "[SAFE] " + dependency;
        }
        return "[" + severity + "] " + dependency + 
               " → " + cveEntry.getCveId() + ": " + cveEntry.getDescription();
    }
}