package com.enterprise.astfixer.util;

import java.io.File;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * SecurityUtils
 * -------------
 * Shared security helpers for AST recipes.
 *
 * Safe-by-default:
 * - If validation cannot be performed confidently -> return false / no-op
 * - Avoid "smart" heuristics that create false confidence
 */
public final class SecurityUtils {

    private SecurityUtils() {
        // utility class
    }

    // =========================================================
    // PATH TRAVERSAL
    // =========================================================

    /** Validate userPath stays inside baseDir after normalize (use before File/Path access). */
    public static boolean isSafePath(String baseDir, String userPath) {
        try {
            if (baseDir == null || userPath == null) return false;
            Path base = Paths.get(baseDir).toAbsolutePath().normalize();
            Path target = base.resolve(userPath).toAbsolutePath().normalize();
            return target.startsWith(base);
        } catch (Exception e) {
            return false;
        }
    }

    /** Canonicalize a filesystem path (best-effort; returns input on failure). */
    public static String canonicalize(String path) {
        try {
            if (path == null) return null;
            return new File(path).getCanonicalPath();
        } catch (Exception e) {
            return path;
        }
    }

    // =========================================================
    // SSRF PROTECTION
    // =========================================================

    /**
     * Conservative SSRF validation: only http/https and blocks any internal/private/local ranges.
     * NOTE: This does not guarantee safety (DNS rebinding exists). Prefer allowlists in production.
     */
    public static boolean isSafeUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = (uri.getScheme() == null) ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) return false;

            String host = uri.getHost();
            if (host == null || host.isBlank()) return false;

            // Resolve; safe-by-default: if resolution fails, reject
            InetAddress addr = InetAddress.getByName(host);

            // Block local/loopback/private/link-local/multicast/unspecified
            if (isBlockedAddress(addr)) return false;

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Allowlist-based SSRF control: only allow specific hosts (recommended enterprise policy). */
    public static boolean isAllowedHost(String url, Set<String> allowlistHosts) {
        try {
            if (allowlistHosts == null || allowlistHosts.isEmpty()) return false;
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            return allowlistHosts.contains(host.toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            return false;
        }
    }

    /** Block common internal address categories (IPv4 + IPv6). */
    public static boolean isBlockedAddress(InetAddress addr) {
        if (addr == null) return true;

        if (addr.isAnyLocalAddress()) return true;       // 0.0.0.0 / ::
        if (addr.isLoopbackAddress()) return true;       // 127.0.0.1 / ::1
        if (addr.isLinkLocalAddress()) return true;      // 169.254.0.0/16 / fe80::/10
        if (addr.isSiteLocalAddress()) return true;      // RFC1918 private ranges
        if (addr.isMulticastAddress()) return true;      // 224.0.0.0/4 / ff00::/8

        // Extra IPv6 checks: Unique Local Address (fc00::/7)
        byte[] bytes = addr.getAddress();
        if (bytes != null && bytes.length == 16) {
            int first = bytes[0] & 0xFF;
            if ((first & 0xFE) == 0xFC) { // fc00::/7
                return true;
            }
        }
        return false;
    }

    // =========================================================
    // COMMAND INJECTION
    // =========================================================

    /** Default command allowlist (demo-friendly). In enterprises this should be configured, not hardcoded. */
    private static final Set<String> SAFE_COMMANDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("ls", "cat", "grep", "echo", "date"))
    );

    /** Checks if the first token is allowlisted (very conservative). */
    public static boolean isSafeCommand(String cmd) {
        if (cmd == null) return false;
        String trimmed = cmd.trim();
        if (trimmed.isEmpty()) return false;
        String first = trimmed.split("\\s+")[0];
        return SAFE_COMMANDS.contains(first);
    }

    /** Tokenize command by whitespace (does not handle quotes; recipes should prefer allowlisted argv arrays). */
    public static String[] tokenizeCommand(String cmd) {
        if (cmd == null) return new String[0];
        return cmd.trim().split("\\s+");
    }

    // =========================================================
    // XSS PROTECTION
    // =========================================================

    /** Minimal HTML escaping (recipes may replace with Apache Commons Text or OWASP Encoder in app code). */
    public static String escapeHtml(String input) {
        if (input == null) return null;
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    /** Quick check if the string looks like it contains HTML tags. */
    public static boolean containsHtml(String input) {
        if (input == null) return false;
        // Cheap heuristic; safe-by-default: don't rely on it for security decisions
        return input.matches(".*<[^>]+>.*");
    }

    // =========================================================
    // TEMPLATE INJECTION
    // =========================================================

    /** Detect common template expression tokens (used to decide whether to sanitize template input). */
    public static boolean containsTemplateExpression(String input) {
        if (input == null) return false;
        return input.contains("${") || input.contains("#{") || input.contains("{{");
    }

    /** Escape common template expression prefixes (best-effort, not a full template sanitizer). */
    public static String sanitizeTemplate(String input) {
        if (input == null) return null;
        return input
                .replace("${", "\\${")
                .replace("#{", "\\#{")
                .replace("{{", "\\{{");
    }

    // =========================================================
    // SQL HELPERS (lightweight heuristics for routing)
    // =========================================================

    /** Rough heuristic: looks like SQL with concatenation. Recipes should still rely on AST patterns. */
    public static boolean looksLikeSqlConcat(String input) {
        if (input == null) return false;
        String lower = input.toLowerCase(Locale.ROOT);
        return (lower.contains("select") || lower.contains("update") || lower.contains("insert") || lower.contains("delete"))
                && input.contains("+");
    }

    /** Rough heuristic for “user-derived” param names (routing only, not enforcement). */
    public static boolean containsUserParam(String expr) {
        if (expr == null) return false;
        String e = expr.toLowerCase(Locale.ROOT);
        return e.contains("request") || e.contains("param") || e.contains("input") || e.contains("id");
    }
}




// package com.enterprise.astfixer.util;

// import java.io.File;
// import java.net.InetAddress;
// import java.net.URI;
// import java.nio.file.Path;
// import java.nio.file.Paths;
// import java.util.*;

// /**
//  * SecurityUtils
//  * -------------
//  * Shared security helpers for AST recipes.
//  *
//  * Provides:
//  *  - Path traversal validation
//  *  - SSRF URL validation
//  *  - Command allowlist
//  *  - HTML escaping helpers
//  *  - Template injection guards
//  *
//  * Safe-by-default design.
//  */
// public class SecurityUtils {

//     /* =========================================================
//        PATH TRAVERSAL
//        ========================================================= */

//     public static boolean isSafePath(String baseDir, String userPath) {
//         try {
//             Path base = Paths.get(baseDir).toAbsolutePath().normalize();
//             Path target = base.resolve(userPath).normalize();

//             return target.startsWith(base);
//         } catch (Exception e) {
//             return false;
//         }
//     }

//     public static String canonicalize(String path) {
//         try {
//             return new File(path).getCanonicalPath();
//         } catch (Exception e) {
//             return path;
//         }
//     }

//     /* =========================================================
//        SSRF PROTECTION
//        ========================================================= */

//     public static boolean isSafeUrl(String url) {
//         try {
//             URI uri = new URI(url);

//             if (!List.of("http", "https").contains(uri.getScheme()))
//                 return false;

//             InetAddress addr = InetAddress.getByName(uri.getHost());

//             if (addr.isAnyLocalAddress()
//                     || addr.isLoopbackAddress()
//                     || addr.isSiteLocalAddress())
//                 return false;

//             return true;

//         } catch (Exception e) {
//             return false;
//         }
//     }

//     public static boolean isAllowedHost(String url, Set<String> allowlist) {
//         try {
//             URI uri = new URI(url);
//             return allowlist.contains(uri.getHost());
//         } catch (Exception e) {
//             return false;
//         }
//     }

//     /* =========================================================
//        COMMAND INJECTION
//        ========================================================= */

//     private static final Set<String> SAFE_COMMANDS =
//             new HashSet<>(Arrays.asList("ls", "cat", "grep", "echo", "date"));

//     public static boolean isSafeCommand(String cmd) {
//         String[] parts = cmd.split(" ");
//         if (parts.length == 0) return false;

//         return SAFE_COMMANDS.contains(parts[0]);
//     }

//     public static String[] tokenizeCommand(String cmd) {
//         return cmd.split(" ");
//     }

//     /* =========================================================
//        XSS PROTECTION
//        ========================================================= */

//     public static String escapeHtml(String input) {
//         if (input == null) return null;

//         return input
//                 .replace("&", "&amp;")
//                 .replace("<", "&lt;")
//                 .replace(">", "&gt;")
//                 .replace("\"", "&quot;")
//                 .replace("'", "&#x27;");
//     }

//     public static boolean containsHtml(String input) {
//         if (input == null) return false;
//         return input.matches(".*<[^>]+>.*");
//     }

//     /* =========================================================
//        TEMPLATE INJECTION
//        ========================================================= */

//     public static boolean containsTemplateExpression(String input) {
//         if (input == null) return false;

//         return input.contains("${")
//                 || input.contains("#{")
//                 || input.contains("{{");
//     }

//     public static String sanitizeTemplate(String input) {
//         if (input == null) return null;

//         return input
//                 .replace("${", "\\${")
//                 .replace("#{", "\\#{")
//                 .replace("{{", "\\{{");
//     }

//     /* =========================================================
//        SQL HELPERS
//        ========================================================= */

//     public static boolean looksLikeSqlConcat(String input) {
//         if (input == null) return false;

//         return input.toLowerCase().contains("select")
//                 && input.contains("+");
//     }

//     public static boolean containsUserParam(String expr) {
//         if (expr == null) return false;

//         return expr.contains("request")
//                 || expr.contains("param")
//                 || expr.contains("input")
//                 || expr.contains("id");
//     }
// }