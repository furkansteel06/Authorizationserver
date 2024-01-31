package com.steel.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationserverApplication /*implements CommandLineRunner*/ {

//    @Autowired
//    RoleRepository repository;
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationserverApplication.class, args);
    }

//    @Override
//    public void run(String... args) throws Exception {
//        Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
//        Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
//        repository.save(adminRole);
//        repository.save(userRole);
//    }
}
