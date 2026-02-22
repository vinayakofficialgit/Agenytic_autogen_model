package com.enterprise.astfixer.recipes;

public class SSRFFixer implements AstRecipe {

    @Override
    public String id() { return "SSRF_AST_FIX"; }

    @Override
    public String vulnerabilityType() { return "SSRF"; }

    @Override
    public boolean apply(CompilationUnit cu, AstContext ctx, AstResult res) {

        final boolean[] changed = {false};

        cu.findAll(ObjectCreationExpr.class).forEach(o -> {
            if (!o.getType().asString().equals("URL")) return;

            MethodCallExpr wrapped =
                    new MethodCallExpr(new NameExpr("URLValidator"), "validate",
                            NodeList.nodeList(o));

            o.replace(wrapped);
            res.notes.add("[ssrf] URL allowlist validation added");
            changed[0] = true;
        });

        return changed[0];
    }
}


// public class SSRFFixer extends ModifierVisitor<Void> {

//     @Override
//     public Visitable visit(ObjectCreationExpr expr, Void arg) {
//         if (expr.getType().asString().equals("URL")) {
//             MethodCallExpr validation = new MethodCallExpr(
//                     new NameExpr("URLValidator"),
//                     "validate",
//                     NodeList.nodeList(expr)
//             );
//             return validation;
//         }
//         return super.visit(expr, arg);
//     }
// }