package com.workshop.model;


import lombok.Data;

@Data
public class AddRoleToUserForm {
    private String username;
    private String roleName;
}
