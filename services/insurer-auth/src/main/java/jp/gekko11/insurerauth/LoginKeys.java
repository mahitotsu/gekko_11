package jp.gekko11.insurerauth;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/** ログインサーバーの公開鍵。認可サーバーの発行の鍵（JWKSource の Bean）と取り違えないよう、包む。 */
record LoginKeys(JWKSource<SecurityContext> source) {
}
