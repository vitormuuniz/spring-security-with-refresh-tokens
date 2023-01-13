package com.workshop.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.workshop.model.AppUser;
import com.workshop.model.Role;

import java.io.IOException;
import java.util.List;

public interface IAppUserService {

    AppUser saveUser(AppUser appUser);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
