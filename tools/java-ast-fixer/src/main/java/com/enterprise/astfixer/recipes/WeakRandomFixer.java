public class WeakRandomFixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("new Random(");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replace("new Random(", "new SecureRandom(")
                .replace("import java.util.Random;",
                         "import java.security.SecureRandom;");

        ctx.setSource(updated);
    }
}