package br.com.examplejwt.security.repository;

import br.com.examplejwt.security.model.entity.Role;
import br.com.examplejwt.security.model.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
