// SPDX-License-Identifier: Apache-2.0

export default [
  {
    files: ["**/*.js"],
    ignores: ["node_modules/**", "coverage/**"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module"
    },
    rules: {
      "no-unused-vars": "error"
    }
  }
];
