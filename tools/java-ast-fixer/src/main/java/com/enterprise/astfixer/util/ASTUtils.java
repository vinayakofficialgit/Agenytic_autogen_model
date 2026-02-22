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
 * Shared AST helper utilities for all security recipes.
 *
 * Goals:
 *  - Prevent duplicated AST traversal logic
 *  - Provide safe rewrite primitives
 *  - Provide SQL concat analyzer
 */
public class ASTUtils {

    /* =========================================================
       Find enclosing structures
       ========================================================= */

    public static Optional<BlockStmt> findBlock(Node node) {
        return node.findAncestor(BlockStmt.class);
    }

    public static Optional<Statement> findStatement(Node node) {
        return node.findAncestor(Statement.class);
    }

    /* =========================================================
       Replace statement safely
       ========================================================= */

    public static boolean replaceStatement(Statement oldStmt, Statement newStmt) {
        try {
            oldStmt.replace(newStmt);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /* =========================================================
       Insert statement before target
       ========================================================= */

    public static boolean insertBefore(BlockStmt block, Statement target, Statement newStmt) {
        int idx = block.getStatements().indexOf(target);
        if (idx < 0) return false;
        block.addStatement(idx, newStmt);
        return true;
    }

    /* =========================================================
       Insert statement after target
       ========================================================= */

    public static boolean insertAfter(BlockStmt block, Statement target, Statement newStmt) {
        int idx = block.getStatements().indexOf(target);
        if (idx < 0) return false;
        block.addStatement(idx + 1, newStmt);
        return true;
    }

    /* =========================================================
       Add import if missing
       ========================================================= */

    public static void ensureImport(CompilationUnit cu, String importName) {
        boolean exists = cu.getImports()
                .stream()
                .anyMatch(i -> i.getNameAsString().equals(importName));

        if (!exists) {
            cu.addImport(importName);
        }
    }

    /* =========================================================
       SQL concat analyzer
       ========================================================= */

    public static class SqlConcatResult {
        public boolean ok;
        public String sqlLiteral;
        public List<Expression> params = new ArrayList<>();
    }

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

        if (!sql.toLowerCase().contains("select")) {
            out.ok = false;
            return out;
        }

        out.ok = true;
        out.sqlLiteral = new StringLiteralExpr(sql).toString();
        return out;
    }

    public static void flattenPlus(Expression e, List<Expression> out) {
        if (e instanceof BinaryExpr
                && ((BinaryExpr) e).getOperator().equals(BinaryExpr.Operator.PLUS)) {

            BinaryExpr b = (BinaryExpr) e;
            flattenPlus(b.getLeft(), out);
            flattenPlus(b.getRight(), out);

        } else {
            out.add(e);
        }
    }

    /* =========================================================
       Build PreparedStatement AST
       ========================================================= */

    public static Statement buildPreparedStatementDecl(String connVar, String psVar, String sqlLiteral) {
        return StaticJavaParser.parseStatement(
                "java.sql.PreparedStatement " + psVar +
                        " = " + connVar + ".prepareStatement(" + sqlLiteral + ");"
        );
    }

    public static Statement buildPreparedSet(String psVar, int index, Expression expr) {
        return StaticJavaParser.parseStatement(
                psVar + ".setObject(" + index + ", " + expr.toString() + ");"
        );
    }

    /* =========================================================
       Build ProcessBuilder AST
       ========================================================= */

    public static Statement buildProcessBuilder(String cmdExpr) {
        return StaticJavaParser.parseStatement(
                "new ProcessBuilder(" + cmdExpr + ".split(\" \")).start();"
        );
    }
}