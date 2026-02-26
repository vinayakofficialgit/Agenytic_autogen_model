package com.enterprise.astfixer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AstContext {

    private final Path filePath;
    private String source;

    public AstContext(String path) throws Exception {
        this.filePath = Paths.get(path);
        this.source = Files.readString(this.filePath);
    }

    public String getSource() {
        return source;
    }

    public void setSource(String updated) {
        this.source = updated;
    }

    public void save() throws Exception {
        Files.writeString(filePath, source);
    }

    public Path getPath() {
        return filePath;
    }
}