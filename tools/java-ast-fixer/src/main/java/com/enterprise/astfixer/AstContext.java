package com.enterprise.astfixer;

import java.nio.file.Path;
import java.util.Map;

/**
 * Context passed to AST recipes
 */
public class AstContext {

    public Path repoRoot;
    public Path file;
    public String vulnerabilityType;
    public String title;
    public String ruleId;
    public String severity;

    // optional metadata (AI hints, tool data)
    public Map<String, Object> metadata;

    public boolean safeMode = true;
}