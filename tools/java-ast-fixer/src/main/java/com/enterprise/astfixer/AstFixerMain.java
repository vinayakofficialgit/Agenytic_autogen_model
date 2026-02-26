package com.enterprise.astfixer;

public class AstFixerMain {

    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.out.println("Usage: AstFixerMain <file> <rule>");
            return;
        }

        String filePath = args[0];
        String ruleName = args[1];

        AstContext ctx = new AstContext(filePath);

        AstRecipe recipe = RecipeFactory.get(ruleName);

        if (recipe == null) {
            System.out.println("Unknown rule: " + ruleName);
            return;
        }

        if (recipe.applies(ctx)) {
            recipe.apply(ctx);
            ctx.save();
            System.out.println("Applied rule: " + ruleName);
        } else {
            System.out.println("Rule not applicable.");
        }
    }
}