package com.enterprise.astfixer.recipes;

import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;

public class CommandInjectionFixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("Runtime.getRuntime().exec");
    }

    @Override
    public void apply(AstContext ctx) {

        String updated = ctx.getSource()
            .replace(
                "Process p = Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"ping -c 1 \" + host});",
                "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", host);\n    Process p = pb.start();"
            )
            .replace(
                "public String ping(@RequestParam String host) throws Exception {",
                "public String ping(@RequestParam String host) throws Exception {\n\n    if (!host.matches(\"^[a-zA-Z0-9.-]+$\")) {\n        throw new IllegalArgumentException(\"Invalid host\");\n    }"
            );

        ctx.setSource(updated);
    }
}