public class Main {

    public static void main(String[] args) throws Exception {

        Path input = Paths.get(args[0]);
        Path output = Paths.get(args[1]);

        ObjectMapper mapper = new ObjectMapper();
        Map payload = mapper.readValue(input.toFile(), Map.class);

        String file = (String) payload.get("file");
        String vuln = (String) payload.get("vuln_type");

        CompilationUnit cu = StaticJavaParser.parse(new File(file));

        switch (vuln) {
            case "SQL_INJECTION":
                new SqlInjectionFixer().visit(cu, null);
                break;
            case "COMMAND_INJECTION":
                new CommandInjectionFixer().visit(cu, null);
                break;
            case "PATH_TRAVERSAL":
                new PathTraversalFixer().visit(cu, null);
                break;
            case "SSRF":
                new SSRFFixer().visit(cu, null);
                break;
            case "XSS":
                new XSSFixer().visit(cu, null);
                break;
            case "TEMPLATE_INJECTION":
                new TemplateInjectionFixer().visit(cu, null);
                break;
        }

        Files.write(Paths.get(file), cu.toString().getBytes());

        Map result = Map.of(
                "ok", true,
                "changed_files", List.of(file),
                "notes", List.of("AST fix applied: " + vuln)
        );

        mapper.writeValue(output.toFile(), result);
    }
}