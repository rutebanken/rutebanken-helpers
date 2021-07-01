package org.entur.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;

import java.util.Collections;
import java.util.Map;


/**
 * Adapt the OAuth2 claims produced by Auth0.
 * The following transformations are performed:
 * <ul>
 *     <li>Copy the namespaced "roles" and "permissions" claims into a "roles" claim.</li>
 *     <li>Copy the namespaced "role_assignments" claim into a "role_assignments" claim.</li>
 *     <li>Copy the namespaced "preferred_name" claim into the OAuth2-standard "preferred_named" claim.</li>
 * </ul>
 * <p>
 * <p>
 * The purpose of this mapping is to simplify the claims produced by Auth0 and make them easier to process by Spring Security.
 * See @{@link JwtRoleAssignmentExtractor}.
 */
class RorAuth0RolesClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {

    private final MappedJwtClaimSetConverter delegate =
            MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());


    private String rorAuth0ClaimNamespace;

    public RorAuth0RolesClaimAdapter(String rorAuth0ClaimNamespace) {
        this.rorAuth0ClaimNamespace = rorAuth0ClaimNamespace;
    }

    @Override
    public Map<String, Object> convert(Map<String, Object> claims) {
        Map<String, Object> convertedClaims = this.delegate.convert(claims);

        // roles assigned to a user are found in the namespaced "roles" claim
        Object roles = convertedClaims.get(rorAuth0ClaimNamespace + "roles");
        if (roles != null) {
            convertedClaims.put(RoROAuth2Claims.OAUTH2_CLAIM_ROLES, roles);
        } else {
            // roles assigned to an application (machine-to-machine service call) are found in the "permissions" claim
            Object permissions = convertedClaims.get("permissions");
            if (permissions != null) {
                convertedClaims.put(RoROAuth2Claims.OAUTH2_CLAIM_ROLES, permissions);
            }
        }

        // role assignments are found in the namespaced "role_assignments" claim
        Object roleAssignments = convertedClaims.get(rorAuth0ClaimNamespace + "role_assignments");
        if (roleAssignments != null) {
            convertedClaims.put(RoROAuth2Claims.OAUTH2_CLAIM_ROLE_ASSIGNMENTS, roleAssignments);
        }

        // user preferred name is found in the namespaced "preferred_username" claim
        Object preferredName = convertedClaims.get(rorAuth0ClaimNamespace + StandardClaimNames.PREFERRED_USERNAME);
        if (preferredName != null) {
            convertedClaims.put(StandardClaimNames.PREFERRED_USERNAME, preferredName);
        }


        return convertedClaims;
    }


}
