package com.depshield.gate;

import com.depshield.model.RiskReport;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class BuildGate {

    private static final String LOG_FILE = "depshield-audit.log";
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public boolean evaluate(List<RiskReport> reports, String buildId) {
        boolean blocked = false;
        StringBuilder logBuilder = new StringBuilder();

        String timestamp = LocalDateTime.now().format(FORMATTER);

        logBuilder.append("\n--------------------------------------\n");
        logBuilder.append("DepShield Scan Report\n");
        logBuilder.append("Build ID  : ").append(buildId).append("\n");
        logBuilder.append("Timestamp : ").append(timestamp).append("\n");
        logBuilder.append("\n---------------------------------------\n");

        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int safeCount = 0;

        for (RiskReport report : reports) {
            logBuilder.append(report.toString()).append("\n");

            switch (report.getSeverity()) {
                case "CRITICAL" -> criticalCount++;
                case "HIGH"     -> highCount++;
                case "MEDIUM"   -> mediumCount++;
                default         -> safeCount++;
            }
        }

        // Policy: CRITICAL or HIGH blocks the build
        if (criticalCount > 0 || highCount > 0) {
            blocked = true;
        }

        logBuilder.append("----------------------------------------\n");
        logBuilder.append("Summary:\n");
        logBuilder.append("  CRITICAL : ").append(criticalCount).append("\n");
        logBuilder.append("  HIGH     : ").append(highCount).append("\n");
        logBuilder.append("  MEDIUM   : ").append(mediumCount).append("\n");
        logBuilder.append("  SAFE     : ").append(safeCount).append("\n");
        logBuilder.append("  DECISION : ")
                  .append(blocked ? "BUILD BLOCKED" : "BUILD PASSED").append("\n");
        logBuilder.append("-----------------------------------------\n");

        // Print to console
        System.out.println(logBuilder.toString());

        // Write to audit log file
        writeToLog(logBuilder.toString());

        return !blocked; // true = passed, false = blocked
    }

    private void writeToLog(String content) {
        try (PrintWriter writer = new PrintWriter(
                new FileWriter(LOG_FILE, true))) { // true = append mode
            writer.println(content);
        } catch (IOException e) {
            System.err.println("[DepShield] Failed to write audit log: " 
                             + e.getMessage());
        }
    }
}