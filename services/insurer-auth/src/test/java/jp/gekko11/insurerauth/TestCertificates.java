package jp.gekko11.insurerauth;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** テスト用の認証局と、SPIFFE の形の証明書（Subject は空、SAN の URI は critical）。 */
final class TestCertificates {

	private static final KeyPair CA = keyPair();

	private TestCertificates() {
	}

	static X509Certificate svid(String spiffeId) {
		try {
			Instant now = Instant.now();
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("O=test-ca"),
					BigInteger.valueOf(now.toEpochMilli()), Date.from(now.minus(1, ChronoUnit.MINUTES)),
					Date.from(now.plus(1, ChronoUnit.HOURS)), new X500Name(""), keyPair().getPublic());
			builder.addExtension(Extension.subjectAlternativeName, true,
					new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, spiffeId)));
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			return new JcaX509CertificateConverter()
				.getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(CA.getPrivate())));
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static KeyPair keyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

}
