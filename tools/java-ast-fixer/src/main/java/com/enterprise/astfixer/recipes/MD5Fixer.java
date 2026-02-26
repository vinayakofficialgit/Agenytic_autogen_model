package com.enterprise.astfixer.recipes;

import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;



public class MD5Fixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("\"MD5\"");
    }

    @Override
    public void apply(AstContext ctx) {
        ctx.setSource(
            ctx.getSource().replace("\"MD5\"", "\"SHA-256\"")
        );
    }
}