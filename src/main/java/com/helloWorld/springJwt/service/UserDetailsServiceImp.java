package com.helloWorld.springJwt.service;

import com.helloWorld.springJwt.model.User;
import com.helloWorld.springJwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImp {

    private final UserRepository repository;

    public UserDetailsServiceImp(UserRepository repository) {
        this.repository = repository;
    }


    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByName(username).orElseThrow(()->new UsernameNotFoundException("User not found"));
    }
}
