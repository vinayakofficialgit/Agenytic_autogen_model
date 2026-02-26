package com.enterprise.astfixer.recipes;

import com.enterprise.astfixer.AstContext;
import com.enterprise.astfixer.AstRecipe;
// import com.enterprise.astfixer.AstFixerMain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SqlInjectionFixer implements AstRecipe {

    // Match: String sql = "SELECT ... NAME = '" + name + "'";
    // Tolerant to whitespace and quoting
    private static final Pattern SQL_CONCAT = Pattern.compile(
            "String\\s+sql\\s*=\\s*\"SELECT\\s+\\*\\s+FROM\\s+USERS\\s+WHERE\\s+NAME\\s*=\\s*'\"\\s*\\+\\s*name\\s*\\+\\s*\"'\"\\s*;",
            Pattern.MULTILINE
    );

    // Match: return jdbc.queryForList(sql);
    private static final Pattern QUERY_FOR_LIST = Pattern.compile(
            "return\\s+jdbc\\.queryForList\\(\\s*sql\\s*\\)\\s*;",
            Pattern.MULTILINE
    );

    @Override
    public boolean applies(AstContext ctx) {
        System.out.println("DEBUG: Checking SqlInjectionFixer applies");
        String src = ctx.getSource();
        return SQL_CONCAT.matcher(src).find() && QUERY_FOR_LIST.matcher(src).find();
    }

    @Override
    public void apply(AstContext ctx) {
        String src = ctx.getSource();

        // 1) Replace concatenated SQL with parameterized SQL
        Matcher m = SQL_CONCAT.matcher(src);
        if (m.find()) {
            src = m.replaceFirst("String sql = \"SELECT * FROM USERS WHERE NAME = ?\";");
        }

        // 2) Replace queryForList(sql) with queryForList(sql, name)
        Matcher q = QUERY_FOR_LIST.matcher(src);
        if (q.find()) {
            src = q.replaceFirst("return jdbc.queryForList(sql, name);");
        }

        ctx.setSource(src);
    }
}