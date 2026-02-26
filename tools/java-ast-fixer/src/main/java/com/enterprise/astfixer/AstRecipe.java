package com.enterprise.astfixer;

public interface AstRecipe {

    boolean applies(AstContext ctx);

    void apply(AstContext ctx) throws Exception;
}