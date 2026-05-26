package com.depshield.parser;

import com.depshield.model.Dependency;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PomParser {

    public List<Dependency> parse(String pomFilePath) {
        List<Dependency> dependencies = new ArrayList<>();

        try {
            // Step 1: Set up the DOM parser
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            // Step 2: Load and parse the XML file into a tree
            Document document = builder.parse(new File(pomFilePath));

            // Step 3: Normalize the tree
            // This ensures text nodes are merged properly
            // Without this, whitespace can split text into multiple nodes
            document.getDocumentElement().normalize();

            // Step 4: Get all <dependency> nodes
            NodeList dependencyNodes = document.getElementsByTagName("dependency");

            // Step 5: Loop through each <dependency> node
            for (int i = 0; i < dependencyNodes.getLength(); i++) {
                Element depElement = (Element) dependencyNodes.item(i);

                String groupId = getTagValue("groupId", depElement);
                String artifactId = getTagValue("artifactId", depElement);
                String version = getTagValue("version", depElement);

                // Some dependencies in pom.xml inherit version from parent
                // We skip those — no version means we can't match against CVEs
                if (groupId != null && artifactId != null && version != null) {
                    dependencies.add(new Dependency(groupId, artifactId, version));
                }
            }

        } catch (Exception e) {
            System.err.println("[DepShield] Failed to parse pom.xml: " + e.getMessage());
        }

        return dependencies;
    }

    // Helper: extracts text content of a named child element
    private String getTagValue(String tag, Element element) {
        NodeList nodeList = element.getElementsByTagName(tag);
        if (nodeList.getLength() == 0) return null;
        String value = nodeList.item(0).getTextContent().trim();
        return value.isEmpty() ? null : value;
    }
}