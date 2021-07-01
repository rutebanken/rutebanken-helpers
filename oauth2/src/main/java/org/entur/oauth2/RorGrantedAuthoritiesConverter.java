package org.entur.oauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * Extract the roles from the JWT token and convert them into Spring Security Authorities.
 * Roles are expected to be defined in the claim {@link RoROAuth2Claims#OAUTH2_CLAIM_ROLES}.
 */
class RorGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : getAuthorities(jwt)) {
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + authority));
        }
        return grantedAuthorities;
    }

    private Collection<String> getAuthorities(Jwt jwt) {
        Object roles = jwt.getClaim(RoROAuth2Claims.OAUTH2_CLAIM_ROLES);
        if (roles == null) {
            return Collections.emptyList();
        } else if (roles instanceof Collection && ((Collection) roles).stream().allMatch(String.class::isInstance)) {
            return (Collection<String>) roles;
        } else {
            throw new IllegalArgumentException("Unknown format for claim " + roles);
        }
    }
}
