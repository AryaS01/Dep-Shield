package com.depshield.model;

public class CVEEntry {
    private String cveId;
    private String groupId;
    private String artifactId;
    private String affectedVersion;
    private String severity;       // CRITICAL, HIGH, MEDIUM, LOW
    private String description;

    // Default constructor — Jackson needs this to deserialize JSON
    public CVEEntry() {}

    public String getCveId() { return cveId; }
    public String getGroupId() { return groupId; }
    public String getArtifactId() { return artifactId; }
    public String getAffectedVersion() { return affectedVersion; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }

    public void setCveId(String cveId) { this.cveId = cveId; }
    public void setGroupId(String groupId) { this.groupId = groupId; }
    public void setArtifactId(String artifactId) { this.artifactId = artifactId; }
    public void setAffectedVersion(String affectedVersion) { this.affectedVersion = affectedVersion; }
    public void setSeverity(String severity) { this.severity = severity; }
    public void setDescription(String description) { this.description = description; }
}