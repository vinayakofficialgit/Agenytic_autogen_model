package com.enterprise.astfixer.recipes;
import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;
public class HardcodedSecretFixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().matches(".*(password|secret|token)\\s*=\\s*\".*\".*");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replaceAll(
                    "(password|secret|token)\\s*=\\s*\".*\"",
                    "$1 = System.getenv(\"APP_$1\")"
                );

        ctx.setSource(updated);
    }
}