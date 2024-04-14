package com.helloWorld.springJwt.service;

import com.helloWorld.springJwt.model.Role;
import com.helloWorld.springJwt.model.Token;
import com.helloWorld.springJwt.model.User;
import com.helloWorld.springJwt.repository.TokenRepository;
import com.helloWorld.springJwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.helloWorld.springJwt.model.AuthenticationResponse;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public AuthenticationService(UserRepository repository,
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 AuthenticationManager authenticationManager,
                                 TokenRepository tokenRepository) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
    }

    public AuthenticationResponse register(User request){

        if (repository.findByEmail(request.getEmail()).isPresent()){
            return  new AuthenticationResponse("bademail");
        }
        else if (repository.findByName(request.getName()).isPresent()){
            return new  AuthenticationResponse("badname");
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user = repository.save(user);
        String jwtTokenStr = jwtService.generateToken(user);

        saveUserToken(jwtTokenStr, user);

        return new AuthenticationResponse(jwtTokenStr);
    }

    private void saveUserToken(String jwtTokenStr, User user) {
        // save the token
        Token token = new Token();
        token.setToken(jwtTokenStr);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(User request){
        Optional<User> databaseUser = repository.findByName(request.getName());
        if (databaseUser.isEmpty()){
            return  new AuthenticationResponse("wrongname");
        }
        else if (!databaseUser.get().getPassword().equals(passwordEncoder.encode(request.getPassword()))){
            return new  AuthenticationResponse("wrongpass");
        }

        User user = repository.findByName(request.getName()).orElseThrow();
        String token = jwtService.generateToken(user);

        revokeAllTokensByUser(user);

        saveUserToken(token,user);
        return new AuthenticationResponse(token);
    }

    private void revokeAllTokensByUser(User user) {
        List<Token> validTokensByUser = tokenRepository.findAllTokensByUser(user.getId());
        if (!validTokensByUser.isEmpty())
            validTokensByUser.forEach(t->t.setLoggedOut(true));
        tokenRepository.saveAll(validTokensByUser);
    }


}
