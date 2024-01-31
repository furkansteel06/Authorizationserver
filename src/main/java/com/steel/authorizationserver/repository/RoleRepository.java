package com.steel.authorizationserver.repository;

import com.steel.authorizationserver.entity.Role;
import com.steel.authorizationserver.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByRole(RoleName roleName);
}
