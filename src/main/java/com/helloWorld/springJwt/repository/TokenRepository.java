package com.helloWorld.springJwt.repository;

import com.helloWorld.springJwt.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer> {
    @Query("""
            Select t from Token t inner join User u
            on t.user.id = u.id
            where t.user.id = :userId and t.isLoggedOut = false
            """)
    List<Token> findAllTokensByUser(Integer userId);

    Optional<Token> findByToken(String token);

}
