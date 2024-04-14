package com.helloWorld.springJwt.config;

import com.helloWorld.springJwt.filter.JwtAuthenticationFilter;
import com.helloWorld.springJwt.service.UserDetailsServiceImp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsServiceImp userDetailsService;
    private final JwtAuthenticationFilter authenticationFilter;
    private final CustomLogoutHandler customLogoutHandler;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    private final static CorsConfiguration corsConfiguration = new CorsConfiguration();
    static {
        corsConfiguration.applyPermitDefaultValues(); // Apply default CORS configuration
    }


    public SecurityConfig(UserDetailsServiceImp userDetailsService,
                          JwtAuthenticationFilter authenticationFilter,
                          CustomLogoutHandler customLogoutHandler,
                          CustomAccessDeniedHandler customAccessDeniedHandler) {
        this.userDetailsService = userDetailsService;
        this.authenticationFilter = authenticationFilter;
        this.customLogoutHandler = customLogoutHandler;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
            return httpSecurity
                    .cors(configure -> configure.configurationSource(request -> corsConfiguration))
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(
                            request-> request.requestMatchers("/login/**","/register/**")
                                    .permitAll()
                                    .anyRequest()
                                    .authenticated()
                    )
                    .exceptionHandling(e -> e.accessDeniedHandler(customAccessDeniedHandler)
                            .authenticationEntryPoint(new HttpStatusEntryPoint((HttpStatus.UNAUTHORIZED))))
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(l->l.logoutUrl("/logout")
                        .addLogoutHandler(customLogoutHandler)
                        .logoutSuccessHandler(
                                (request, response, authentication) -> SecurityContextHolder.clearContext()
                        ))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }




}
