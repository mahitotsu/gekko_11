// TypeScript の lint（D-47）。typescript-eslint の推奨の規則と、React の hooks の 2 つの規則だけを使い、整形は扱わない。
// Keycloak のテーマのスクリプト（services/insurer-login/theme）は、製品のものを写して直したので、対象にしない。
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/node_modules/**", "**/dist/**", "services/**"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    rules: {
      // secure の版の差し替えは、受け口と同じ形の引数を受けて使わない。使わない名前は _ で始める
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    // テストは、型のない JSON の応答を読んで確かめる。応答ごとに型を書くと、何を確かめるかが読みにくくなる
    files: ["test/**/*.ts", "packages/*/test/**/*.ts"],
    rules: { "@typescript-eslint/no-explicit-any": "off" },
  },
  {
    files: ["packages/customer-app/web/**/*.tsx", "packages/customer-app/web/**/*.ts"],
    plugins: { "react-hooks": reactHooks },
    rules: { "react-hooks/rules-of-hooks": "error", "react-hooks/exhaustive-deps": "warn" },
  },
);
