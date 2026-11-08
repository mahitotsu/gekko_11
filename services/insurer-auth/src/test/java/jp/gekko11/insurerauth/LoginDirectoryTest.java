package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;

/** ログインサーバーの資格情報から、passkey の識別子と公開鍵を取り出す（D-42）。 */
class LoginDirectoryTest {

	private final LoginDirectory directory = new LoginDirectory(
			new AuthProperties("http://auth", "td", "secure", "http://login", "http://login/jwks", "http://127.0.0.1:1", "/none"));

	@Test
	void readsBothBase64AndBase64Url() {
		// 識別子のバイトに 0xfb 0xff を含めると、base64 では「+/」、base64url では「-_」になる
		Map<String, String> standard = this.directory.keyOf("{\"credentialId\":\"+/8A\",\"credentialPublicKey\":\"pQECAyY=\"}");
		Map<String, String> url = this.directory.keyOf("{\"credentialId\":\"-_8A\",\"credentialPublicKey\":\"pQECAyY\"}");
		assertThat(standard).isEqualTo(url).containsEntry("id", "-_8A").containsEntry("coseKey", "pQECAyY");
	}

	@Test
	void reportsWhatIsMissing() {
		assertThatThrownBy(() -> this.directory.keyOf("{\"credentialId\":\"AAAA\"}")).hasMessageContaining("値がない");
	}

}
