package com.enterprise.astfixer.util;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;

import java.util.*;

/**
 * ASTUtils
 * --------
 * Shared AST helper utilities for security recipes.
 *
 * Design goals:
 * - Keep recipes small and consistent (common AST operations live here)
 * - Safe-by-default: helpers return Optional/boolean instead of throwing
 * - Provide small builders for common secure replacements (PreparedStatement, ProcessBuilder)
 */
public final class ASTUtils {

    private ASTUtils() {
        // utility class
    }

    // =========================================================
    // Find enclosing structures
    // =========================================================

    /** Find nearest enclosing BlockStmt (used to insert statements next to a vulnerable call). */
    public static Optional<BlockStmt> findBlock(Node node) {
        return node.findAncestor(BlockStmt.class);
    }

    /** Find nearest enclosing Statement (used to replace the exact statement containing a vulnerable call). */
    public static Optional<Statement> findStatement(Node node) {
        return node.findAncestor(Statement.class);
    }

    // =========================================================
    // Safe AST edits
    // =========================================================

    /** Replace a statement safely; returns false if JavaParser refuses the replacement. */
    public static boolean replaceStatement(Statement oldStmt, Statement newStmt) {
        try {
            oldStmt.replace(newStmt);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    /** Insert a statement before a target statement inside a block. */
    public static boolean insertBefore(BlockStmt block, Statement target, Statement newStmt) {
        int idx = block.getStatements().indexOf(target);
        if (idx < 0) return false;
        block.addStatement(idx, newStmt);
        return true;
    }

    /** Insert a statement after a target statement inside a block. */
    public static boolean insertAfter(BlockStmt block, Statement target, Statement newStmt) {
        int idx = block.getStatements().indexOf(target);
        if (idx < 0) return false;
        // idx+1 can equal size() which is valid (append)
        block.addStatement(idx + 1, newStmt);
        return true;
    }

    /** Insert multiple statements before a target (useful for PreparedStatement + setObject lines). */
    public static boolean insertBeforeMany(BlockStmt block, Statement target, List<Statement> newStmts) {
        int idx = block.getStatements().indexOf(target);
        if (idx < 0) return false;
        for (int i = 0; i < newStmts.size(); i++) {
            block.addStatement(idx + i, newStmts.get(i));
        }
        return true;
    }

    // =========================================================
    // Imports
    // =========================================================

    /** Ensure an import exists (recipes call this to avoid compile errors). */
    public static void ensureImport(CompilationUnit cu, String importName) {
        boolean exists = cu.getImports().stream().anyMatch(i -> i.getNameAsString().equals(importName));
        if (!exists) cu.addImport(importName);
    }

    // =========================================================
    // Safe parsing helpers
    // =========================================================

    /** Parse a Java statement safely; returns empty if parsing fails. */
    public static Optional<Statement> tryParseStatement(String stmt) {
        try {
            return Optional.of(StaticJavaParser.parseStatement(stmt));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    /** Parse an expression safely; returns empty if parsing fails. */
    public static Optional<Expression> tryParseExpression(String expr) {
        try {
            return Optional.of(StaticJavaParser.parseExpression(expr));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    // =========================================================
    // SQL concat analyzer
    // =========================================================

    public static final class SqlConcatResult {
        /** True when we confidently split into SQL literal + params. */
        public boolean ok;
        /** Quoted SQL string with ? placeholders (e.g., "SELECT ... WHERE id=?"). */
        public String sqlLiteral;
        /** Collected parameter expressions (e.g., id, userId, request.getParameter("x")). */
        public List<Expression> params = new ArrayList<>();
    }

    /**
     * Analyze `"... " + x + " ..."` style concatenation and convert it to SQL literal + param list.
     * Safe-by-default: returns ok=false if it can't confidently derive a query.
     */
    public static SqlConcatResult analyzeSqlConcat(BinaryExpr expr) {
        List<Expression> parts = new ArrayList<>();
        flattenPlus(expr, parts);

        SqlConcatResult out = new SqlConcatResult();

        if (parts.isEmpty() || !(parts.get(0) instanceof StringLiteralExpr)) {
            out.ok = false;
            return out;
        }

        StringBuilder sb = new StringBuilder();
        for (Expression p : parts) {
            if (p instanceof StringLiteralExpr) {
                sb.append(((StringLiteralExpr) p).asString());
            } else {
                sb.append("?");
                out.params.add(p);
            }
        }

        String sql = sb.toString();
        // Reduce false positives: require typical SQL verb
        String lower = sql.toLowerCase(Locale.ROOT);
        if (!(lower.contains("select") || lower.contains("update") || lower.contains("insert") || lower.contains("delete"))) {
            out.ok = false;
            return out;
        }

        out.ok = true;
        out.sqlLiteral = new StringLiteralExpr(sql).toString(); // includes quotes
        return out;
    }

    /** Flatten nested PLUS binary expressions into a linear list of parts. */
    public static void flattenPlus(Expression e, List<Expression> out) {
        if (e instanceof BinaryExpr && ((BinaryExpr) e).getOperator().equals(BinaryExpr.Operator.PLUS)) {
            BinaryExpr b = (BinaryExpr) e;
            flattenPlus(b.getLeft(), out);
            flattenPlus(b.getRight(), out);
        } else {
            out.add(e);
        }
    }

    // =========================================================
    // Builders
    // =========================================================

    /** Build: `java.sql.PreparedStatement ps = conn.prepareStatement("...");` */
    public static Statement buildPreparedStatementDecl(String connVar, String psVar, String sqlLiteral) {
        return StaticJavaParser.parseStatement(
                "java.sql.PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(" + sqlLiteral + ");"
        );
    }

    /** Build: `ps.setObject(1, expr);` */
    public static Statement buildPreparedSet(String psVar, int index, Expression expr) {
        return StaticJavaParser.parseStatement(psVar + ".setObject(" + index + ", " + expr + ");");
    }

    /**
     * Build: `new ProcessBuilder(cmd.split(" ")).start();`
     * Note: recipes should prefer allowlist + fixed command arrays when possible.
     */
    public static Statement buildProcessBuilderSplit(String cmdExpr) {
        return StaticJavaParser.parseStatement("new ProcessBuilder(" + cmdExpr + ".split(\" \")).start();");
    }

    /** Build: `new ProcessBuilder("ls","-al",dir).start();` (recommended when you can form an allowlisted argv). */
    public static Statement buildProcessBuilderArgs(List<String> argvLiterals) {
        String joined = String.join(", ", argvLiterals);
        return StaticJavaParser.parseStatement("new ProcessBuilder(" + joined + ").start();");
    }
}




// package com.enterprise.astfixer.util;

// import com.github.javaparser.StaticJavaParser;
// import com.github.javaparser.ast.CompilationUnit;
// import com.github.javaparser.ast.Node;
// import com.github.javaparser.ast.expr.*;
// import com.github.javaparser.ast.stmt.*;

// import java.util.*;

// /**
//  * ASTUtils
//  * --------
//  * Shared AST helper utilities for all security recipes.
//  *
//  * Goals:
//  *  - Prevent duplicated AST traversal logic
//  *  - Provide safe rewrite primitives
//  *  - Provide SQL concat analyzer
//  */
// public class ASTUtils {

//     /* =========================================================
//        Find enclosing structures
//        ========================================================= */

//     public static Optional<BlockStmt> findBlock(Node node) {
//         return node.findAncestor(BlockStmt.class);
//     }

//     public static Optional<Statement> findStatement(Node node) {
//         return node.findAncestor(Statement.class);
//     }

//     /* =========================================================
//        Replace statement safely
//        ========================================================= */

//     public static boolean replaceStatement(Statement oldStmt, Statement newStmt) {
//         try {
//             oldStmt.replace(newStmt);
//             return true;
//         } catch (Exception e) {
//             return false;
//         }
//     }

//     /* =========================================================
//        Insert statement before target
//        ========================================================= */

//     public static boolean insertBefore(BlockStmt block, Statement target, Statement newStmt) {
//         int idx = block.getStatements().indexOf(target);
//         if (idx < 0) return false;
//         block.addStatement(idx, newStmt);
//         return true;
//     }

//     /* =========================================================
//        Insert statement after target
//        ========================================================= */

//     public static boolean insertAfter(BlockStmt block, Statement target, Statement newStmt) {
//         int idx = block.getStatements().indexOf(target);
//         if (idx < 0) return false;
//         block.addStatement(idx + 1, newStmt);
//         return true;
//     }

//     /* =========================================================
//        Add import if missing
//        ========================================================= */

//     public static void ensureImport(CompilationUnit cu, String importName) {
//         boolean exists = cu.getImports()
//                 .stream()
//                 .anyMatch(i -> i.getNameAsString().equals(importName));

//         if (!exists) {
//             cu.addImport(importName);
//         }
//     }

//     /* =========================================================
//        SQL concat analyzer
//        ========================================================= */

//     public static class SqlConcatResult {
//         public boolean ok;
//         public String sqlLiteral;
//         public List<Expression> params = new ArrayList<>();
//     }

//     public static SqlConcatResult analyzeSqlConcat(BinaryExpr expr) {
//         List<Expression> parts = new ArrayList<>();
//         flattenPlus(expr, parts);

//         SqlConcatResult out = new SqlConcatResult();

//         if (parts.isEmpty() || !(parts.get(0) instanceof StringLiteralExpr)) {
//             out.ok = false;
//             return out;
//         }

//         StringBuilder sb = new StringBuilder();

//         for (Expression p : parts) {
//             if (p instanceof StringLiteralExpr) {
//                 sb.append(((StringLiteralExpr) p).asString());
//             } else {
//                 sb.append("?");
//                 out.params.add(p);
//             }
//         }

//         String sql = sb.toString();

//         if (!sql.toLowerCase().contains("select")) {
//             out.ok = false;
//             return out;
//         }

//         out.ok = true;
//         out.sqlLiteral = new StringLiteralExpr(sql).toString();
//         return out;
//     }

//     public static void flattenPlus(Expression e, List<Expression> out) {
//         if (e instanceof BinaryExpr
//                 && ((BinaryExpr) e).getOperator().equals(BinaryExpr.Operator.PLUS)) {

//             BinaryExpr b = (BinaryExpr) e;
//             flattenPlus(b.getLeft(), out);
//             flattenPlus(b.getRight(), out);

//         } else {
//             out.add(e);
//         }
//     }

//     /* =========================================================
//        Build PreparedStatement AST
//        ========================================================= */

//     public static Statement buildPreparedStatementDecl(String connVar, String psVar, String sqlLiteral) {
//         return StaticJavaParser.parseStatement(
//                 "java.sql.PreparedStatement " + psVar +
//                         " = " + connVar + ".prepareStatement(" + sqlLiteral + ");"
//         );
//     }

//     public static Statement buildPreparedSet(String psVar, int index, Expression expr) {
//         return StaticJavaParser.parseStatement(
//                 psVar + ".setObject(" + index + ", " + expr.toString() + ");"
//         );
//     }

//     /* =========================================================
//        Build ProcessBuilder AST
//        ========================================================= */

//     public static Statement buildProcessBuilder(String cmdExpr) {
//         return StaticJavaParser.parseStatement(
//                 "new ProcessBuilder(" + cmdExpr + ".split(\" \")).start();"
//         );
//     }
// }