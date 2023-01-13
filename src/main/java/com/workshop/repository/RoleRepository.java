package com.workshop.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.workshop.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
