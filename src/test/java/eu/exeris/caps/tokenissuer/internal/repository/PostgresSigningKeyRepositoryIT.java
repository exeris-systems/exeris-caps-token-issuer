package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.TokenIssuerModule;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException;
import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException.Reason;
import eu.exeris.caps.tokenissuer.internal.DefaultJwksPublisher;
import eu.exeris.caps.tokenissuer.internal.DefaultSigningKeyRotation;
import eu.exeris.caps.tokenissuer.internal.custody.KeyEncryptionKeyring;
import eu.exeris.caps.tokenissuer.internal.custody.SigningKeyEnvelope;
import eu.exeris.caps.tokenissuer.testing.JdbcTransactionalExecutor;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Signing-key custody against a real PostgreSQL.
 *
 * <p>The database comes from {@code EXERIS_TEST_PG_URL}, {@code EXERIS_TEST_PG_USER} and
 * {@code EXERIS_TEST_PG_PASSWORD} when they are set; otherwise from a Testcontainers PostgreSQL
 * with a generated password. Without either, the class is skipped locally and fails when {@code CI} is set.
 */
class PostgresSigningKeyRepositoryIT {

    private static PostgreSQLContainer<?> container;
    private static JdbcTransactionalExecutor tx;

    @BeforeAll
    static void startDatabase() throws Exception {
        String url = System.getenv("EXERIS_TEST_PG_URL");
        if (url != null && !url.isBlank()) {
            tx = new JdbcTransactionalExecutor(url, System.getenv("EXERIS_TEST_PG_USER"), System.getenv("EXERIS_TEST_PG_PASSWORD"));
        } else {
            // CI sets CI=true, and there a missing Docker daemon must fail the build, not skip the test.
            if (System.getenv("CI") != null) {
                assertThat(DockerClientFactory.instance().isDockerAvailable())
                        .as("CI needs a Docker daemon for the PostgreSQL integration test").isTrue();
            } else {
                Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                        "no EXERIS_TEST_PG_URL and no Docker; skipping PostgreSQL integration test");
            }
            container = new PostgreSQLContainer<>("postgres:17-alpine")
                    .withPassword(UUID.randomUUID().toString());
            container.start();
            tx = new JdbcTransactionalExecutor(container.getJdbcUrl(), container.getUsername(), container.getPassword());
        }
        String ddl = Files.readString(Path.of("src/main/resources/schema/token-issuer-schema.sql"), StandardCharsets.UTF_8);
        try (Connection c = tx.open(); Statement s = c.createStatement()) {
            s.execute(ddl);
        }
    }

    @AfterAll
    static void stopDatabase() {
        if (container != null) {
            container.stop();
        }
    }

    @BeforeEach
    void truncate() throws Exception {
        try (Connection c = tx.open(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE exeris_signing_keys");
        }
    }

    private static KeyEncryptionKeyring ring(String spec) {
        return KeyEncryptionKeyring.parse("TEST", spec);
    }

    private static byte[] storedPrivateKey(String kid) throws Exception {
        try (Connection c = tx.open();
             PreparedStatement ps = c.prepareStatement("SELECT private_key_pkcs8 FROM exeris_signing_keys WHERE kid = ?")) {
            ps.setString(1, kid);
            try (ResultSet rs = ps.executeQuery()) {
                assertThat(rs.next()).isTrue();
                return rs.getBytes(1);
            }
        }
    }

    private static List<Byte> bytes(byte[] array) {
        Byte[] boxed = new Byte[array.length];
        for (int i = 0; i < array.length; i++) {
            boxed[i] = array[i];
        }
        return List.of(boxed);
    }

    @Test
    @DisplayName("a booted module stores keys sealed, and its tokens verify with jose4j from the JWKS alone")
    void moduleBootSealsKeysAndIssuesVerifiableTokens() throws Exception {
        Map<String, String> env = Map.of(
                TokenIssuerConfig.ENV_ISSUER, TestSupport.ISSUER,
                TokenIssuerConfig.ENV_AUDIENCE, TestSupport.AUDIENCE,
                TokenIssuerConfig.ENV_MANUAL_ROTATION, "true",
                KeyEncryptionKeyring.ENV_KEKS, "kek-it:" + TestSupport.newKek());
        TokenIssuerModule module = new TokenIssuerModule(env, tx, null, null, null);
        module.initialize();
        module.ready();

        SigningKeyInfo active = module.signingKeyRotation().activeKey();
        byte[] stored = storedPrivateKey(active.kid());
        assertThat(SigningKeyEnvelope.kekIdOf(stored)).isEqualTo("kek-it");

        PostgresSigningKeyRepository repository = new PostgresSigningKeyRepository(tx, ring(env.get(KeyEncryptionKeyring.ENV_KEKS)));
        byte[] pkcs8 = repository.findByKid(active.kid()).orElseThrow().privateKeyPkcs8Bytes();
        assertThat(Collections.indexOfSubList(bytes(stored), bytes(pkcs8))).isEqualTo(-1);

        UUID subject = UUID.randomUUID();
        IssuedAccessToken token = module.accessTokenIssuer().issueAccessToken(
                TokenIssueRequest.builder().subjectId(subject).tenantId("tenant-it").build());
        JwtClaims claims = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(
                        new JsonWebKeySet(module.jwksPublisher().getJwksJson()).getJsonWebKeys()))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.EDDSA)
                .setExpectedIssuer(TestSupport.ISSUER)
                .setExpectedAudience(TestSupport.AUDIENCE)
                .setRequireExpirationTime()
                .setRequireNotBefore()
                .build()
                .processToClaims(token.token());
        assertThat(claims.getSubject()).isEqualTo(subject.toString());
        assertThat(claims.getStringClaimValue("tid")).isEqualTo("tenant-it");
        module.terminate();
    }

    @Test
    @DisplayName("a different KEK cannot open stored keys, and issuance fails instead of falling back")
    void wrongKekFailsToDecrypt() {
        String kek = TestSupport.newKek();
        MutableClock clock = new MutableClock(Instant.parse("2026-02-01T00:00:00Z"));
        PostgresSigningKeyRepository writer = new PostgresSigningKeyRepository(tx, ring("k1:" + kek));
        String kid = new DefaultSigningKeyRotation(writer, TestSupport.config(), null, null, clock).ensureActiveKey().kid();

        PostgresSigningKeyRepository wrong = new PostgresSigningKeyRepository(tx, ring("k1:" + TestSupport.newKek()));
        assertThatThrownBy(() -> wrong.findByKid(kid))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));

        PostgresSigningKeyRepository unknown = new PostgresSigningKeyRepository(tx, ring("k2:" + kek));
        assertThatThrownBy(unknown::findActive)
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.UNKNOWN_KEK));

        Map<String, String> env = Map.of(
                TokenIssuerConfig.ENV_ISSUER, TestSupport.ISSUER,
                TokenIssuerConfig.ENV_AUDIENCE, TestSupport.AUDIENCE,
                TokenIssuerConfig.ENV_MANUAL_ROTATION, "true",
                KeyEncryptionKeyring.ENV_KEKS, "k1:" + TestSupport.newKek());
        TokenIssuerModule module = new TokenIssuerModule(env, tx, null, null, null);
        assertThatThrownBy(() -> module.accessTokenIssuer().issueAccessToken(UUID.randomUUID(), null))
                .isInstanceOf(SigningKeyCustodyException.class);
    }

    @Test
    @DisplayName("a row holding a plaintext private key is refused on read")
    void plaintextRowRefused() throws Exception {
        try (Connection c = tx.open(); PreparedStatement ps = c.prepareStatement("""
                INSERT INTO exeris_signing_keys (kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at)
                VALUES ('k-plain', 'EdDSA', '{}', ?, ?, 'ACTIVE', now(), now() + interval '1 day')
                """)) {
            ps.setBytes(1, new byte[32]);
            ps.setBytes(2, new byte[]{0x30, 0x2e, 0x02, 0x01, 0x00});
            ps.executeUpdate();
        }
        PostgresSigningKeyRepository repository = new PostgresSigningKeyRepository(tx, ring("k1:" + TestSupport.newKek()));
        assertThatThrownBy(repository::findActive)
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.NOT_SEALED));
    }

    @Test
    @DisplayName("KEK rotation: prepend a new KEK, reseal, then the old KEK can be dropped")
    void kekRotationAndReseal() {
        String oldKek = TestSupport.newKek();
        String newKek = TestSupport.newKek();
        MutableClock clock = new MutableClock(Instant.parse("2026-02-01T00:00:00Z"));
        PostgresSigningKeyRepository underOld = new PostgresSigningKeyRepository(tx, ring("old:" + oldKek));
        DefaultSigningKeyRotation rotation = new DefaultSigningKeyRotation(underOld, TestSupport.config(), null, null, clock);
        rotation.ensureActiveKey();
        rotation.rotateKeys();

        PostgresSigningKeyRepository both = new PostgresSigningKeyRepository(tx, ring("new:" + newKek + ",old:" + oldKek));
        assertThat(both.findAllInfo()).hasSize(2);
        assertThat(both.resealWithActiveKek()).isEqualTo(2);
        assertThat(both.resealWithActiveKek()).isZero();

        PostgresSigningKeyRepository onlyNew = new PostgresSigningKeyRepository(tx, ring("new:" + newKek));
        assertThat(onlyNew.findAllInfo()).hasSize(2);
    }

    @Test
    @DisplayName("rotation overlap holds through PostgreSQL: the old key is published until maxTokenTtl + clockSkew")
    void rotationOverlapInPostgres() {
        MutableClock clock = new MutableClock(Instant.parse("2026-02-01T00:00:00Z"));
        TokenIssuerConfig config = TestSupport.config();
        PostgresSigningKeyRepository repository = new PostgresSigningKeyRepository(tx, ring("k1:" + TestSupport.newKek()));
        DefaultSigningKeyRotation rotation = new DefaultSigningKeyRotation(repository, config, null, null, clock);
        DefaultJwksPublisher jwks = new DefaultJwksPublisher(repository, clock);

        String first = rotation.ensureActiveKey().kid();
        clock.advance(java.time.Duration.ofMinutes(10));
        String second = TestSupport.rotateAndActivate(rotation, clock, config).kid();
        Instant windowEnd = clock.instant().plus(config.publicationOverlap());

        clock.set(windowEnd.minusSeconds(1));
        assertThat(jwks.getJwksDocument().keys()).extracting(k -> k.get("kid")).containsExactlyInAnyOrder(first, second);

        clock.set(windowEnd);
        assertThat(jwks.getJwksDocument().keys()).extracting(k -> k.get("kid")).containsExactly(second);
        assertThat(rotation.retireExpiredKeys()).isEqualTo(1);
        assertThat(repository.findByKid(first).orElseThrow().state()).isEqualTo(KeyState.RETIRED);
    }

    @Test
    @DisplayName("the JWKS and the key listing read public data only: they work with no usable KEK and never unseal")
    void jwksAndListingNeverUnsealPrivateKeys() {
        MutableClock clock = new MutableClock(Instant.parse("2026-02-01T00:00:00Z"));
        TokenIssuerConfig config = TestSupport.config();
        PostgresSigningKeyRepository writer = new PostgresSigningKeyRepository(tx, ring("k1:" + TestSupport.newKek()));
        DefaultSigningKeyRotation rotation = new DefaultSigningKeyRotation(writer, config, null, null, clock);
        String first = rotation.ensureActiveKey().kid();
        String second = TestSupport.rotateAndActivate(rotation, clock, config).kid();
        String pending = rotation.rotateKeys().kid();

        PostgresSigningKeyRepository noKek = new PostgresSigningKeyRepository(tx, ring("other:" + TestSupport.newKek()));
        assertThatThrownBy(() -> noKek.findByKid(first)).isInstanceOf(SigningKeyCustodyException.class);

        DefaultJwksPublisher jwks = new DefaultJwksPublisher(noKek, clock);
        assertThat(jwks.getJwksDocument().keys()).extracting(k -> k.get("kid"))
                .containsExactlyInAnyOrder(first, second, pending);
        assertThat(new DefaultSigningKeyRotation(noKek, config, null, null, clock).listKeyGenerations())
                .extracting(SigningKeyInfo::state)
                .containsExactlyInAnyOrder(KeyState.RETIRING, KeyState.ACTIVE, KeyState.PENDING);
    }
}
