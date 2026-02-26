public class MD5Fixer implements AstRecipe {

    @Override
    public boolean applies(AstContext ctx) {
        return ctx.getSource().contains("MD5");
    }

    @Override
    public void apply(AstContext ctx) {
        String updated = ctx.getSource()
                .replace("\"MD5\"", "\"SHA-256\"");

        ctx.setSource(updated);
    }
}