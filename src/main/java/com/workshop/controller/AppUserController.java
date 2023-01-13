package com.workshop.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.workshop.model.AddRoleToUserForm;
import com.workshop.model.AppUser;
import com.workshop.model.Role;
import com.workshop.security.filter.FilterUtils;
import com.workshop.service.impl.AppUserService;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AppUserController {

    private final AppUserService appUserService;

    @PostMapping("/users")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser appUser) {
        return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.saveUser(appUser));
    }

    @PostMapping("/roles")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.saveRole(role));
    }

    @PostMapping("/roles/add-to-user")
    public ResponseEntity<Void> addRoleTouser(@RequestBody AddRoleToUserForm addRoleToUserDTO) {
        appUserService.addRoleToUser(addRoleToUserDTO.getUsername(), addRoleToUserDTO.getRoleName());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/users")
    public ResponseEntity<?> getUsers(@RequestParam(required = false) String username) {
        if (Objects.isNull(username)) {
            return ResponseEntity.ok(appUserService.getUsers());
        }
        return ResponseEntity.ok(appUserService.getUser(username));
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        appUserService.refreshToken(request, response);
    }
}
