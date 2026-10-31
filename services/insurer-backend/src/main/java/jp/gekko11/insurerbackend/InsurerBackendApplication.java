package jp.gekko11.insurerbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** 保険会社のシステム（insurer-backend）。案に署名し、申込みを確かめて契約を記録し、顧客へ直接送る（architecture の 2 章）。 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class InsurerBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(InsurerBackendApplication.class, args);
	}

}
