package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.tokenissuer.api.JwksDocument;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.internal.boundary.JwksHttpRoute;
import eu.exeris.caps.tokenissuer.internal.crypto.Rfc8037JwksBuilder;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Default implementation of {@link JwksPublisher}.
 *
 * @since 0.1.0
 */
public final class DefaultJwksPublisher implements JwksPublisher {

    private final SigningKeyRepository repository;
    private final KeyRotationPolicy policy;

    public DefaultJwksPublisher(SigningKeyRepository repository, KeyRotationPolicy policy) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
    }

    @Override
    public String getJwksJson() {
        return getJwksDocument().rawJson();
    }

    @Override
    public JwksDocument getJwksDocument() {
        Instant now = Instant.now();
        List<SigningKeyRecord> records = repository.findPublishable(now, policy.overlapWindow());
        List<Map<String, String>> keyList = new ArrayList<>(records.size());
        for (SigningKeyRecord rec : records) {
            Map<String, String> jwk = Rfc8037JwksBuilder.buildJwkParams(rec.kid(), rec.publicKeyRawBytes());
            keyList.add(jwk);
        }
        return Rfc8037JwksBuilder.buildJwksDocument(keyList);
    }

    @Override
    public void registerBoundaryRoute(ApiSurfaceRegistry registry) {
        Objects.requireNonNull(registry, "ApiSurfaceRegistry must not be null");
        registry.registerRoute(JwksHttpRoute.createRoute(this::getJwksJson));
    }
}
