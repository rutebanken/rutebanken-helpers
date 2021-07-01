package org.entur.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.rutebanken.helper.organisation.RoleAssignment;
import org.rutebanken.helper.organisation.RoleAssignmentExtractor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Extract @{@link RoleAssignment}s from @{@link JwtAuthenticationToken}.
 * Role assignments are expected to be defined in the claim {@link RoROAuth2Claims#OAUTH2_CLAIM_ROLE_ASSIGNMENTS}, in JSON format.
 */
public class JwtRoleAssignmentExtractor implements RoleAssignmentExtractor {

    private static ObjectMapper mapper = new ObjectMapper();

    public List<RoleAssignment> getRoleAssignmentsForUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return getRoleAssignmentsForUser(auth);
    }

    @Override
    public List<RoleAssignment> getRoleAssignmentsForUser(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) auth;
            Jwt jwt = (Jwt) jwtAuthenticationToken.getPrincipal();
            Object claim = jwt.getClaim(RoROAuth2Claims.OAUTH2_CLAIM_ROLE_ASSIGNMENTS);
            if (claim == null) {
                return Collections.emptyList();
            }
            List<Object> roleAssignmentList;
            if (claim instanceof List) {
                roleAssignmentList = (List) claim;
            } else if (claim instanceof String) {
                roleAssignmentList = Arrays.asList(((String) claim).split("##"));
            } else {
                throw new IllegalArgumentException("Unsupported claim type: " + claim);
            }

            return roleAssignmentList.stream().map(JwtRoleAssignmentExtractor::parse).collect(Collectors.toList());
        } else {
            throw new AccessDeniedException("Not authenticated with token");
        }
    }

    private static RoleAssignment parse(Object roleAssignment) {
        if (roleAssignment instanceof Map) {
            return mapper.convertValue(roleAssignment, RoleAssignment.class);
        }
        try {
            return mapper.readValue((String) roleAssignment, RoleAssignment.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Exception while parsing role assignments from JSON", e);
        }
    }
}
