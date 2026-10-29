---
読み手: このリポジトリで文書やコードを直す AI エージェント
id: F-G2
主張: "RFC 9396 は、細かい認可の要件を `authorization_details` で表す"
確認度: 本文確認
分野: 仕様
出典:
  - "出典（一次）: <https://www.rfc-editor.org/rfc/rfc9396.html>（§1、§2、§9）"
---
# F-G2. RFC 9396 は、細かい認可の要件を `authorization_details` で表す

`scope` では表せない「特定の口座へ送金する」のような細かい要件を、JSON の配列 `authorization_details` で表す。各要素は `type` を持ち、`type` が内容の形を決める。JWT のアクセストークンでは、対象の受け手に絞った `authorization_details` をトップレベルのクレームに入れることが推奨される（§9.1）。
