import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import jsxA11y from "eslint-plugin-jsx-a11y";

// What this is for: the type checker catches the shape of a component, and
// the end-to-end tests will catch what a page does. Neither notices a
// control nobody can reach with a keyboard, or an effect whose dependencies
// quietly lie. That is what these rules are here for.
export default tseslint.config(
  { ignores: ["dist", "src/api", "src/routeTree.gen.ts"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2023,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
      "jsx-a11y": jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // Kumo's Input and Textarea render a real input, and every label here
      // wraps its control, which is what associates them. The rule cannot
      // see through a component, so it is told which ones are controls.
      "jsx-a11y/label-has-associated-control": [
        "error",
        { controlComponents: ["Input", "Textarea", "Select", "Checkbox"], depth: 3 },
      ],
      // An unused argument named with a leading underscore is a signature
      // being honoured, not a mistake.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    // Every route file exports a Route object built by createFileRoute
    // beside its component, which is how the router works. Fast refresh
    // gives that up, and a page reload during development is a fair price.
    files: ["src/routes/**/*.tsx"],
    rules: { "react-refresh/only-export-components": "off" },
  },
  {
    // Tests run in Node and may reach for its globals.
    files: ["**/*.test.{ts,tsx}", "*.config.{ts,js}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
);
