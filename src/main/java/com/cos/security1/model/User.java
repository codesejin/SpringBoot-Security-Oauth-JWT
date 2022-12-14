package com.cos.security1.model;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Setter
@Getter
@Entity(name = "users")
public class User {
    @Id // primart key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;

    private String password;

    private String email;

    private String role;//ROLE_USER, ROLE_ADMIN

    private String provider;
    private String providerId;

//    private  Timestamp loginDate; // 로그인할때마다 날짜를 넣어둠
    @CreationTimestamp
    private Timestamp createDate;

}
