package com.cos.security1.repository;


import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD 함수를 JpaRepository가 들고 있음
//@Repository라는 어노테이션이 없어도 IoC되요. 이유는 JpaRepository를 상속했기 때문에
public interface UserRepository  extends JpaRepository<User, Integer> {
    //findBy규칙 -> username문법
    // select * from user where username = 1?
    //아래처럼 쓰면 위에처럼 호출됨 = jpa Query Methods
    public User findByUsername(String username);

    //select * from user where email = ?
    //public User findByEmail();
}