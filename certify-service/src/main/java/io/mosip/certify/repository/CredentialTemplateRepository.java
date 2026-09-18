package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.entity.CredentialTemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialTemplateRepository extends JpaRepository<CredentialTemplate, CredentialTemplateId> {
    Optional<CredentialTemplate> findByIdAndVersion(String id, Integer version);
    Optional<CredentialTemplate> findFirstByIdOrderByVersionDesc(String id);
}
