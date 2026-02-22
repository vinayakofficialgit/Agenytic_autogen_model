package com.enterprise.astfixer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * AstFixerMain
 * ============
 * Production AST autofix dispatcher
 *
 * Responsibilities:
 * ✔ Load request JSON
 * ✔ Build execution context
 * ✔ Select AST recipe via registry
 * ✔ Execute safe AST transform
 * ✔ Persist result JSON
 *
 * Plugin architecture:
 * Recipes implement AstRecipe interface
 */
public class AstFixerMain {

    // ======================
    // JSON CONTRACT
    // ======================
    static class Req {
        public String repo_root;
        public String file;
        public String vuln_type;
        public String title;
        public String rule_id;
        public String severity;
    }

    static class Res {
        public boolean ok = true;
        public List<String> changed_files = new ArrayList<>();
        public List<String> notes = new ArrayList<>();
    }

    // ======================
    // RECIPE REGISTRY
    // ======================
    private static final Map<String, AstRecipe> registry = new HashMap<>();

    static {
        register(new SqlInjectionFixer());
        register(new CommandInjectionFixer());
        register(new PathTraversalFixer());
        register(new SSRFFixer());
        register(new XSSFixer());
        register(new TemplateInjectionFixer());
    }

    private static void register(AstRecipe recipe) {
        registry.put(recipe.vulnerabilityType(), recipe);
    }

    // ======================
    // MAIN
    // ======================
    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.err.println("Usage: AstFixerMain <in.json> <out.json>");
            System.exit(2);
        }

        ObjectMapper om = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        Req req = om.readValue(new File(args[0]), Req.class);
        Res res = new Res();

        Path repoRoot = Path.of(req.repo_root).toAbsolutePath().normalize();
        Path target = repoRoot.resolve(req.file).toAbsolutePath().normalize();

        // SAFETY CHECK
        if (!target.startsWith(repoRoot) || !Files.exists(target)) {
            res.notes.add("[ast] target missing/outside repo: " + req.file);
            om.writeValue(new File(args[1]), res);
            return;
        }

        // PARSE AST
        CompilationUnit cu = StaticJavaParser.parse(Files.readString(target));

        // BUILD CONTEXT
        AstContext ctx = new AstContext();
        ctx.repoRoot = repoRoot;
        ctx.file = target;
        ctx.vulnerabilityType = req.vuln_type;
        ctx.title = req.title;
        ctx.ruleId = req.rule_id;
        ctx.severity = req.severity;

        AstResult astResult = new AstResult();

        // SELECT RECIPE
        AstRecipe recipe = registry.get(req.vuln_type);

        if (recipe == null) {
            res.notes.add("[ast] unsupported vuln_type: " + req.vuln_type);
        } else {
            try {
                boolean changed = recipe.apply(cu, ctx, astResult);

                if (changed) {
                    Files.writeString(target, cu.toString());
                    res.changed_files.add(req.file);
                    res.notes.add("[ast] file updated: " + req.file);
                } else {
                    res.notes.add("[ast] no confident transform applied");
                }

            } catch (Exception ex) {
                res.ok = false;
                res.notes.add("[ast] recipe failure: " + ex.getMessage());
            }
        }

        // MERGE NOTES
        res.notes.addAll(astResult.notes);

        om.writeValue(new File(args[1]), res);
    }
}



// package com.enterprise.astfixer;

// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.fasterxml.jackson.databind.SerializationFeature;
// import com.github.javaparser.StaticJavaParser;
// import com.github.javaparser.ast.CompilationUnit;

// import java.io.File;
// import java.nio.file.Files;
// import java.nio.file.Path;
// import java.util.*;

// /**
//  * AstFixerMain
//  * ============
//  * Production AST autofix dispatcher
//  *
//  * Responsibilities:
//  * ✔ Load request JSON
//  * ✔ Build execution context
//  * ✔ Select AST recipe via registry
//  * ✔ Execute safe AST transform
//  * ✔ Persist result JSON
//  *
//  * Plugin architecture:
//  * Recipes implement AstRecipe interface
//  */
// public class AstFixerMain {

//     // ======================
//     // JSON CONTRACT
//     // ======================
//     static class Req {
//         public String repo_root;
//         public String file;
//         public String vuln_type;
//         public String title;
//         public String rule_id;
//         public String severity;
//     }

//     static class Res {
//         public boolean ok = true;
//         public List<String> changed_files = new ArrayList<>();
//         public List<String> notes = new ArrayList<>();
//     }

//     // ======================
//     // RECIPE REGISTRY
//     // ======================
//     private static final Map<String, AstRecipe> registry = new HashMap<>();

//     static {
//         register(new SqlInjectionFixer());
//         register(new CommandInjectionFixer());
//         register(new PathTraversalFixer());
//         register(new SSRFFixer());
//         register(new XSSFixer());
//         register(new TemplateInjectionFixer());
//     }

//     private static void register(AstRecipe recipe) {
//         registry.put(recipe.vulnerabilityType(), recipe);
//     }

//     // ======================
//     // MAIN
//     // ======================
//     public static void main(String[] args) throws Exception {

//         if (args.length < 2) {
//             System.err.println("Usage: AstFixerMain <in.json> <out.json>");
//             System.exit(2);
//         }

//         ObjectMapper om = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

//         Req req = om.readValue(new File(args[0]), Req.class);
//         Res res = new Res();

//         Path repoRoot = Path.of(req.repo_root).toAbsolutePath().normalize();
//         Path target = repoRoot.resolve(req.file).toAbsolutePath().normalize();

//         // SAFETY CHECK
//         if (!target.startsWith(repoRoot) || !Files.exists(target)) {
//             res.notes.add("[ast] target missing/outside repo: " + req.file);
//             om.writeValue(new File(args[1]), res);
//             return;
//         }

//         // PARSE AST
//         CompilationUnit cu = StaticJavaParser.parse(Files.readString(target));

//         // BUILD CONTEXT
//         AstContext ctx = new AstContext();
//         ctx.repoRoot = repoRoot;
//         ctx.file = target;
//         ctx.vulnerabilityType = req.vuln_type;
//         ctx.title = req.title;
//         ctx.ruleId = req.rule_id;
//         ctx.severity = req.severity;

//         AstResult astResult = new AstResult();

//         // SELECT RECIPE
//         AstRecipe recipe = registry.get(req.vuln_type);

//         if (recipe == null) {
//             res.notes.add("[ast] unsupported vuln_type: " + req.vuln_type);
//         } else {
//             try {
//                 boolean changed = recipe.apply(cu, ctx, astResult);

//                 if (changed) {
//                     Files.writeString(target, cu.toString());
//                     res.changed_files.add(req.file);
//                     res.notes.add("[ast] file updated: " + req.file);
//                 } else {
//                     res.notes.add("[ast] no confident transform applied");
//                 }

//             } catch (Exception ex) {
//                 res.ok = false;
//                 res.notes.add("[ast] recipe failure: " + ex.getMessage());
//             }
//         }

//         // MERGE NOTES
//         res.notes.addAll(astResult.notes);

//         om.writeValue(new File(args[1]), res);
//     }
// }