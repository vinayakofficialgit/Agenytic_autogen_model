package com.enterprise.astfixer.recipes;
import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;

public class SHA1Fixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("SHA1") ||
               ctx.getSource().contains("SHA-1");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replace("\"SHA1\"", "\"SHA-256\"")
                .replace("\"SHA-1\"", "\"SHA-256\"");

        ctx.setSource(updated);
    }
}