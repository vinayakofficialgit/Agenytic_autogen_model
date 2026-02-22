package com.enterprise.astfixer.recipes;

public class CommandInjectionFixer implements AstRecipe {

    @Override
    public String id() { return "CMD_AST_FIX"; }

    @Override
    public String vulnerabilityType() { return "COMMAND_INJECTION"; }

    @Override
    public boolean apply(CompilationUnit cu, AstContext ctx, AstResult res) {

        final boolean[] changed = {false};

        cu.findAll(MethodCallExpr.class).forEach(mce -> {
            if (!mce.getNameAsString().equals("exec")) return;

            String scope = mce.getScope().map(Expression::toString).orElse("");
            if (!scope.contains("Runtime.getRuntime")) return;

            Statement original = mce.findAncestor(Statement.class).orElse(null);
            if (original == null) return;

            try {
                Statement replacement =
                        StaticJavaParser.parseStatement(
                                "new ProcessBuilder(cmd.split(\" \")).start();"
                        );

                original.replace(replacement);
                res.notes.add("[cmd] ProcessBuilder applied");
                changed[0] = true;

            } catch (Exception e) {
                res.notes.add("[cmd] safe transform failed");
            }
        });

        return changed[0];
    }
}

// public class CommandInjectionFixer extends ModifierVisitor<Void> {

//     @Override
//     public Visitable visit(MethodCallExpr m, Void arg) {
//         if (m.getNameAsString().equals("exec")) {
//             ObjectCreationExpr pb = new ObjectCreationExpr(
//                     null,
//                     new ClassOrInterfaceType(null, "ProcessBuilder"),
//                     m.getArguments()
//             );
//             return pb;
//         }
//         return super.visit(m, arg);
//     }
// }