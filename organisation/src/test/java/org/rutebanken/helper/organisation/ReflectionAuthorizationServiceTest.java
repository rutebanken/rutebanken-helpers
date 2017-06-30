package org.rutebanken.helper.organisation;

import org.junit.Test;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.rutebanken.helper.organisation.AuthorizationConstants.ENTITY_TYPE;

/**
 * Example content for token's role assignment.
 * [
 * {
 * “r”: “editStops”,
 * “o”: “OST”,
 * “z”: “01",
 * “e”: {
 * “EntityType”: [
 * “StopPlace”, "Parking" {
 * ],
 * “StopPlaceType”: [
 * “!airport”,
 * “!railStation”
 * ],
 * versionComment
 * “Submode”: [
 * “!railReplacementBus”
 * ]
 * }
 * }
 * ]
 */
public class ReflectionAuthorizationServiceTest {


    private ReflectionAuthorizationService reflectionAuthorizationService = new ReflectionAuthorizationService();

    @Test
    public void authorizedForLegalStopPlaceTypesWhenOthersBlacklisted() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("StopPlaceType", "!railStation")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(true));
    }

    @Test
    public void authorizedForLegalSubmodeTypesWhenStarValue() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "*")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.submode = "someValue";

        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, "editStops"), is(true));
    }

    @Test
    public void shouldBeAuthorizedForSubmodeTypesWhenExplicitWhiteListed() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "someValue")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.submode = "someValue";

        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, "editStops"), is(true));
    }

    @Test
    public void authorizedWhenAllTypesEntityType() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "*")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), roleAssignment.r);
        assertThat(authorized, is(true));
    }

    @Test
    public void notAuthorizedWhenRolesMismatch() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "*")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), "somethingElse");
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedWhenEmptyRoleAssignmentEntityClassifications() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedForIncorrectSubMode() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "!railReplacementBus")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;

        // Submode is not allowed
        stopPlace.submode = "railReplacementBus";

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedForIncorrectEntityType() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .build();

        // Not stop place
        Object object = new Object();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, object, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedToEditAirport() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }


    public static class StopPlace {
        public enum StopPlaceType {
            ONSTREET_BUS("onstreetBus"),
            ONSTREET_TRAM("onstreetTram"),
            AIRPORT("airport");
            private final String value;

            StopPlaceType(String v) {
                value = v;
            }

            public static StopPlaceType fromValue(String value) {
                return Stream.of(StopPlaceType.values()).filter(stopType -> stopType.value.equals(value)).findFirst().get();
            }

            public String value() {
                return value;
            }
        }

        public StopPlaceType stopPlaceType;
        public String submode;
    }

}