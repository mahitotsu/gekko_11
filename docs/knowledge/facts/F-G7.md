---
読み手: このリポジトリで文書やコードを直す AI エージェント
id: F-G7
主張: "Secure Payment Confirmation は、取引内容をブラウザの画面に出して署名させる"
確認度: 本文確認
分野: 仕様
出典:
  - "出典（一次）: <https://www.w3.org/TR/secure-payment-confirmation/>（§4.10.1、§4.11）"
---
# F-G7. Secure Payment Confirmation は、取引内容をブラウザの画面に出して署名させる

Secure Payment Confirmation（SPC）は、WebAuthn を使い、ユーザーが取引内容を確認したことの暗号学的な証拠を作る。ブラウザが支払先、金額などを自分の UI に表示して、同意を取る（§4.10.1）。取引内容は `challenge` に入るのではなく、`payment` 拡張の入力として渡され、署名付きの結果に含まれる。`challenge` は再送攻撃の防止にだけ使う。仕様の状態は Candidate Recommendation Draft（2026-10-13 付）である。
