package org.springframework.samples.petclinic.security;

import java.util.Optional;

import org.springframework.samples.petclinic.model.Pet;
import org.springframework.samples.petclinic.model.Visit;
import org.springframework.samples.petclinic.service.ClinicService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * Object-level authorization for the OWNER role: an owner may only read resources that belong to them.
 * <p>
 * The owner identity comes from the {@code owner_id} claim set by Keycloak, never from the request,
 * which prevents IDOR (changing an id in the URL to read someone else's data).
 * Used in {@code @PreAuthorize} expressions as {@code @ownership.isOwner(authentication, #ownerId)}.
 * A missing resource returns {@code false} (403), so the API does not reveal which ids exist.
 */
@Component("ownership")
public class OwnershipEvaluator {

    static final String OWNER_ID_CLAIM = "owner_id";

    private final ClinicService clinicService;

    public OwnershipEvaluator(ClinicService clinicService) {
        this.clinicService = clinicService;
    }

    public boolean isOwner(Authentication authentication, Integer ownerId) {
        return ownerId != null && ownerIdOf(authentication).map(ownerId::equals).orElse(false);
    }

    public boolean ownsPet(Authentication authentication, Integer petId) {
        if (petId == null) {
            return false;
        }
        Pet pet = clinicService.findPetById(petId);
        return pet != null && pet.getOwner() != null && isOwner(authentication, pet.getOwner().getId());
    }

    public boolean ownsVisit(Authentication authentication, Integer visitId) {
        if (visitId == null) {
            return false;
        }
        Visit visit = clinicService.findVisitById(visitId);
        return visit != null && visit.getPet() != null && ownsPet(authentication, visit.getPet().getId());
    }

    private Optional<Integer> ownerIdOf(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuth)) {
            return Optional.empty();
        }
        Object claim = jwtAuth.getToken().getClaims().get(OWNER_ID_CLAIM);
        if (claim instanceof Number number) {
            return Optional.of(number.intValue());
        }
        if (claim instanceof String text && text.matches("\\d{1,9}")) {
            return Optional.of(Integer.valueOf(text));
        }
        return Optional.empty();
    }
}
