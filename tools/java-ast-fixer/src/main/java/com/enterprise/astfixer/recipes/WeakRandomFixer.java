package com.enterprise.astfixer.recipes;

import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;

public class WeakRandomFixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("new Random(");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replace("new Random(", "new java.security.SecureRandom(")
                .replace("import java.util.Random;",
                         "import java.security.SecureRandom;");

        ctx.setSource(updated);
    }
}