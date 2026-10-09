package eu.exeris.caps.tokenissuer.api;

import java.util.UUID;

/**
 * Service providing short-lived access JWT tokens signed with EdDSA over Ed25519.
 *
 * <p>Supports both direct binary subject/session calls (structurally compatible with
 * {@code exeris-caps-session-management}) and rich request envelopes specifying roles,
 * audience, custom claims, and TTL overrides.
 *
 * @since 0.1.0
 */
public interface AccessTokenIssuer {

    /**
     * Issues an access token using standard policy defaults for the given subject and session.
     *
     * @param subjectId identity subject identifier; non-null
     * @param sessionId session identifier; non-null
     * @return newly issued access token
     */
    IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId);

    /**
     * Issues an access token according to the provided request parameters.
     *
     * @param request token issuance request; non-null
     * @return newly issued access token
     */
    IssuedAccessToken issueAccessToken(TokenIssueRequest request);
}
