package com.enterprise.astfixer;

import com.github.javaparser.ast.CompilationUnit;
import java.util.List;

/**
 * AstRecipe
 * ---------
 * Contract for all AST security fix recipes.
 *
 * Every vulnerability fixer must:
 * 1️⃣ Detect if pattern exists
 * 2️⃣ Apply AST transformation safely
 * 3️⃣ Report notes
 * 4️⃣ Return whether change occurred
 *
 * Safe-by-default:
 * If transformation is not confident → return false (no-op)
 */
public interface AstRecipe {

    /**
     * Apply AST transformation.
     *
     * @param cu   CompilationUnit representing parsed Java file
     * @param res  Result collector (notes, changed files)
     * @return true if AST was modified
     */
    boolean apply(CompilationUnit cu, AstFixerMain.Res res);

    /**
     * Recipe identifier (used for logging & metrics)
     */
    String id();

    /**
     * Vulnerability type supported (used by dispatcher)
     * Example:
     * SQL_INJECTION
     * COMMAND_INJECTION
     * PATH_TRAVERSAL
     * SSRF
     * XSS
     * TEMPLATE_INJECTION
     */
    String vulnerabilityType();
}