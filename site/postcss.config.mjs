// Tailwind CSS を PostCSS で通す。Vite のプラグイン版は、ルートの別の版の Vite を読んでしまうので使わない（D-49）。
export default { plugins: { "@tailwindcss/postcss": {} } };
