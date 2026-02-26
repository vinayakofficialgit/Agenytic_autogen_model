package com.enterprise.astfixer;

import com.enterprise.astfixer.recipes.*;

public class RecipeFactory {

    public static AstRecipe get(String name) {

        switch (name) {
            case "WeakRandomFixer":
                return new WeakRandomFixer();
            case "MD5Fixer":
                return new MD5Fixer();
            case "SHA1Fixer":
                return new SHA1Fixer();
            case "HardcodedSecretFixer":
                return new HardcodedSecretFixer();
            case "CryptoStrengthFixer":
                return new CryptoStrengthFixer();
            case "CommandInjectionFixer":
                return new CommandInjectionFixer();
            case "SqlInjectionFixer":
                return new SqlInjectionFixer();
            default:
                return null;
        }
    }
}