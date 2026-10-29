export const config = {
  // 乗っ取られた営業 AI エージェントを再現する(デモ用)。true だと、提出する直前に、取決めの範囲で最も保険料が高い案へ書き換える。
  // 本物の Claude をプロンプトインジェクションで確実に操ることはできないので、決まった動きで代役させる。
  tamper: process.env.SALES_AGENT_TAMPER === "1",
};
export const hasClaude = () => Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY);
