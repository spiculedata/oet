// Minimal flat ESLint config for TypeScript. Expand per lane as the surface grows.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // functions/ (Firebase deploy wrapper) and deploy/ (scripts) have their own toolchains; dist/ is built output.
  { ignores: ["dist/", "node_modules/", "functions/", "deploy/"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_" },
      ],
    },
  },
);
