package com.enterprise.astfixer.recipes;

public class XSSFixer implements AstRecipe {

    @Override
    public String id() { return "XSS_AST_FIX"; }

    @Override
    public String vulnerabilityType() { return "XSS"; }

    @Override
    public boolean apply(CompilationUnit cu, AstContext ctx, AstResult res) {

        final boolean[] changed = {false};

        cu.findAll(BinaryExpr.class).forEach(b -> {

            if (b.getOperator() != BinaryExpr.Operator.PLUS) return;

            MethodCallExpr escape =
                    new MethodCallExpr(new NameExpr("StringEscapeUtils"),
                            "escapeHtml4",
                            NodeList.nodeList(b));

            b.replace(escape);
            res.notes.add("[xss] HTML sanitizer applied");
            changed[0] = true;
        });

        return changed[0];
    }
}

// public class XSSFixer extends ModifierVisitor<Void> {

//     @Override
//     public Visitable visit(BinaryExpr expr, Void arg) {
//         if (expr.getOperator() == BinaryExpr.Operator.PLUS) {
//             MethodCallExpr escape = new MethodCallExpr(
//                     new NameExpr("StringEscapeUtils"),
//                     "escapeHtml4",
//                     NodeList.nodeList(expr)
//             );
//             return escape;
//         }
//         return super.visit(expr, arg);
//     }
// }