package jp.gekko11.insurerbackend;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** テストの差し替え。防御は外した ID だけ無効にし、passkey の公開鍵は手元の認証器から返す。 */
@TestConfiguration
class TestBackendConfig {

	static final Map<String, String> OFF = new ConcurrentHashMap<>();

	static final Map<String, List<Map<String, String>>> PASSKEYS = new ConcurrentHashMap<>();

	@Bean
	@Primary
	Defenses testDefenses() {
		return new Defenses() {
			@Override
			public boolean enabled(String id) {
				return !OFF.containsKey(id);
			}

			@Override
			public Optional<String> variant(String id) {
				return Optional.ofNullable(OFF.get(id));
			}
		};
	}

	@Bean
	@Primary
	PasskeyDirectory testPasskeys() {
		return (user) -> PASSKEYS.getOrDefault(user, List.of());
	}

}
