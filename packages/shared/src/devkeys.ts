// 教材用の固定鍵。「営業員(AI)自身が申込みに署名する」という不十分な例(シナリオ7)を再現するためだけに使う。
// 秘密鍵をリポジトリに置くのは教材だからであり、本番では絶対にしないこと。
import type { JWK } from "jose";

export const agentKey: { pub: JWK; priv: JWK } = {
  "pub": {
    "kty": "EC",
    "x": "lylaMtu9oZ56ueH5q4j3jpKuORqMClepmfv-D7PWrZ4",
    "y": "hYmLAA7SDD7GnmDTPTgG65zMSGqaxcS_TpICtiK3GdI",
    "crv": "P-256"
  },
  "priv": {
    "kty": "EC",
    "x": "lylaMtu9oZ56ueH5q4j3jpKuORqMClepmfv-D7PWrZ4",
    "y": "hYmLAA7SDD7GnmDTPTgG65zMSGqaxcS_TpICtiK3GdI",
    "crv": "P-256",
    "d": "WxqmvdGOCslwTaKRDHEUNc60OUgniLjEbypKY1PQb_Y"
  }
};
