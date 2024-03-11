module.exports = {
    root: true,
    env: {
        node: true,
    },
    extends: [
        "@polyfillhq/eslint-config/node",
    ],

    rules: {
        "@typescript-eslint/indent": ["error", 4],
        "@typescript-eslint/quotes": ["error", "double"],
        "@typescript-eslint/comma-dangle": "off",
        "@typescript-eslint/default-param-last": "off",
        "no-param-reassign": "off",
    },
    ignore: [
        "bin/senv",
    ],
};
