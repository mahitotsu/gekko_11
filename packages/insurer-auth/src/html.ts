const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

export function page(title: string, body: string): string {
  return `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:560px;margin:2rem auto;padding:0 16px;color:#222}
button,select,input{font:inherit;padding:.5rem 1rem;margin:.25rem 0}button{cursor:pointer}
.card{border:1px solid #ccc;border-radius:8px;padding:12px 16px;margin:12px 0;background:#fafafa}.muted{color:#666;font-size:.9em}</style>
<body><h1>🏢 保険会社</h1>${body}</body></html>`;
}
export { esc };
