package com.depshield;

import com.depshield.model.Dependency;
import com.depshield.parser.PomParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PomParserTest {

    private PomParser parser;

    @BeforeEach
    void setUp() {
        parser = new PomParser();
    }

    @Test
    void shouldParseVulnerablePom() {
        // Get the test resource path
        String path = getClass().getClassLoader()
                .getResource("vulnerable-pom.xml").getPath();

        List<Dependency> deps = parser.parse(path);

        assertEquals(2, deps.size());
        assertEquals("org.apache.logging.log4j", deps.get(0).getGroupId());
        assertEquals("log4j-core", deps.get(0).getArtifactId());
        assertEquals("2.14.1", deps.get(0).getVersion());
    }

    @Test
    void shouldParseSafePom() {
        String path = getClass().getClassLoader()
                .getResource("safe-pom.xml").getPath();

        List<Dependency> deps = parser.parse(path);

        assertEquals(1, deps.size());
        assertEquals("jackson-databind", deps.get(0).getArtifactId());
    }

    @Test
    void shouldSkipDependenciesWithNoVersion() {
        String path = getClass().getClassLoader()
                .getResource("no-version-pom.xml").getPath();

        List<Dependency> deps = parser.parse(path);

        // spring-web has no version → skipped
        // jackson-databind has version → included
        assertEquals(1, deps.size());
        assertEquals("jackson-databind", deps.get(0).getArtifactId());
    }

    @Test
    void shouldReturnEmptyListForMissingFile() {
        List<Dependency> deps = parser.parse("nonexistent-pom.xml");
        assertTrue(deps.isEmpty());
    }
}