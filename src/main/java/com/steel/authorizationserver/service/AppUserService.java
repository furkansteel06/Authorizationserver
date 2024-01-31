package com.steel.authorizationserver.service;

import com.steel.authorizationserver.dto.CreateAppUserDto;
import com.steel.authorizationserver.dto.MessageDto;
import com.steel.authorizationserver.entity.AppUser;
import com.steel.authorizationserver.entity.Role;
import com.steel.authorizationserver.enums.RoleName;
import com.steel.authorizationserver.repository.AppUserRepository;
import com.steel.authorizationserver.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final RoleRepository repository;
    private  final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto){
        AppUser appUser = AppUser.builder()
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = repository.findByRole(RoleName.valueOf(r))
                    .orElseThrow(() -> new RuntimeException("role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);
        return new MessageDto("user " + appUser.getUsername() + " saved");
    }
}
