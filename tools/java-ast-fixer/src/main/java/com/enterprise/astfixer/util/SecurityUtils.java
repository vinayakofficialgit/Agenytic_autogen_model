package com.enterprise.astfixer.util;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * SecurityUtils
 * -------------
 * Shared security helpers for AST recipes.
 *
 * Provides:
 *  - Path traversal validation
 *  - SSRF URL validation
 *  - Command allowlist
 *  - HTML escaping helpers
 *  - Template injection guards
 *
 * Safe-by-default design.
 */
public class SecurityUtils {

    /* =========================================================
       PATH TRAVERSAL
       ========================================================= */

    public static boolean isSafePath(String baseDir, String userPath) {
        try {
            Path base = Paths.get(baseDir).toAbsolutePath().normalize();
            Path target = base.resolve(userPath).normalize();

            return target.startsWith(base);
        } catch (Exception e) {
            return false;
        }
    }

    public static String canonicalize(String path) {
        try {
            return new File(path).getCanonicalPath();
        } catch (Exception e) {
            return path;
        }
    }

    /* =========================================================
       SSRF PROTECTION
       ========================================================= */

    public static boolean isSafeUrl(String url) {
        try {
            URI uri = new URI(url);

            if (!List.of("http", "https").contains(uri.getScheme()))
                return false;

            InetAddress addr = InetAddress.getByName(uri.getHost());

            if (addr.isAnyLocalAddress()
                    || addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress())
                return false;

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isAllowedHost(String url, Set<String> allowlist) {
        try {
            URI uri = new URI(url);
            return allowlist.contains(uri.getHost());
        } catch (Exception e) {
            return false;
        }
    }

    /* =========================================================
       COMMAND INJECTION
       ========================================================= */

    private static final Set<String> SAFE_COMMANDS =
            new HashSet<>(Arrays.asList("ls", "cat", "grep", "echo", "date"));

    public static boolean isSafeCommand(String cmd) {
        String[] parts = cmd.split(" ");
        if (parts.length == 0) return false;

        return SAFE_COMMANDS.contains(parts[0]);
    }

    public static String[] tokenizeCommand(String cmd) {
        return cmd.split(" ");
    }

    /* =========================================================
       XSS PROTECTION
       ========================================================= */

    public static String escapeHtml(String input) {
        if (input == null) return null;

        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    public static boolean containsHtml(String input) {
        if (input == null) return false;
        return input.matches(".*<[^>]+>.*");
    }

    /* =========================================================
       TEMPLATE INJECTION
       ========================================================= */

    public static boolean containsTemplateExpression(String input) {
        if (input == null) return false;

        return input.contains("${")
                || input.contains("#{")
                || input.contains("{{");
    }

    public static String sanitizeTemplate(String input) {
        if (input == null) return null;

        return input
                .replace("${", "\\${")
                .replace("#{", "\\#{")
                .replace("{{", "\\{{");
    }

    /* =========================================================
       SQL HELPERS
       ========================================================= */

    public static boolean looksLikeSqlConcat(String input) {
        if (input == null) return false;

        return input.toLowerCase().contains("select")
                && input.contains("+");
    }

    public static boolean containsUserParam(String expr) {
        if (expr == null) return false;

        return expr.contains("request")
                || expr.contains("param")
                || expr.contains("input")
                || expr.contains("id");
    }
}