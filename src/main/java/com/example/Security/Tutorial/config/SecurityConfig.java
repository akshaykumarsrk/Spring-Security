package com.example.Security.Tutorial.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception
    {
        httpSecurity.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/home").permitAll()   // to make home page public i.e without login
//                .requestMatchers("/api/v1/student").hasRole("STUDENT/**")  // STUDENT can access only /** it means wild card i.e anything that come after this all the APIs included in this
                .requestMatchers("api/v1/admin").hasRole("ADMIN")    // ADMIN can access only
                .requestMatchers("/api/v1/student").hasAnyRole("STUDNT", "ADMIN")  // muliple roles
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); // support from postman
//                .formLogin();  // does not support postman i.e form comes and postman doesnot support frontend

        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user1 = User.builder()
                .username("kohli")
                .password(passwordEncoder().encode("kohli123"))
                .roles("STUDENT")
                .build();

        UserDetails user2 = User.builder()
                .username("rohit")
                .password(passwordEncoder().encode("rohit123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }
}
