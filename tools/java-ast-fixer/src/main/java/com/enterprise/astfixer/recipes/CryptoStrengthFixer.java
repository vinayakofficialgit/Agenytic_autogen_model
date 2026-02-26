package com.enterprise.astfixer.recipes;
import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;

public class CryptoStrengthFixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("128");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replace("128", "256");

        ctx.setSource(updated);
    }
}