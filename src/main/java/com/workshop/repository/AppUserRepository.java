package com.workshop.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.workshop.model.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
