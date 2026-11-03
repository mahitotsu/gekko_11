package jp.gekko11.insureraudit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** 監査サービス。記録を作る者と別のサービスとして、契約ごとに、自己申告と第三者の記録を突き合わせる（D-17）。 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class InsurerAuditApplication {

	public static void main(String[] args) {
		SpringApplication.run(InsurerAuditApplication.class, args);
	}

}
