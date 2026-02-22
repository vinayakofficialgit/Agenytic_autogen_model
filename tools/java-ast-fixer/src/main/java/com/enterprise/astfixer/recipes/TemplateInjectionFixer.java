package com.enterprise.astfixer.recipes;

public class TemplateInjectionFixer implements AstRecipe {

    @Override
    public String id() { return "TPL_AST_FIX"; }

    @Override
    public String vulnerabilityType() { return "TEMPLATE_INJECTION"; }

    @Override
    public boolean apply(CompilationUnit cu, AstContext ctx, AstResult res) {

        final boolean[] changed = {false};

        cu.findAll(MethodCallExpr.class).forEach(m -> {
            if (!m.getNameAsString().equals("render")) return;

            m.setName("safeRender");
            res.notes.add("[template] safe render enforced");
            changed[0] = true;
        });

        return changed[0];
    }
}

// public class TemplateInjectionFixer extends ModifierVisitor<Void> {

//     @Override
//     public Visitable visit(MethodCallExpr expr, Void arg) {
//         if (expr.getNameAsString().equals("render")) {
//             expr.setName("safeRender");
//         }
//         return super.visit(expr, arg);
//     }
// }