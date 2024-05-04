package com.greatlearning.ssrs.security.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.greatlearning.ssrs.security.service.impl.SsrsUserDetailsServiceImpl;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;    

@Configuration
public class SsrsSecurityConfiguration {

	@Bean
	public UserDetailsService userDetailsService() {
		return new SsrsUserDetailsServiceImpl();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider ssrsDaoAuthenticationProvider() {

		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	  http.authorizeRequests()
	    .requestMatchers("/","/list", "/displayStudentForm", "/save").hasAnyAuthority("NORMAL_USER","ADMIN_USER")
	    .requestMatchers("/displayStudentForm_Update","/delete").hasAuthority("ADMIN_USER")
	    .anyRequest().authenticated()
	    .and()
	    .formLogin().loginProcessingUrl("/login").successForwardUrl("/list").permitAll()
	    .and()
	    .logout().logoutSuccessUrl("/login").permitAll()
	    .and()
	    .exceptionHandling().accessDeniedPage("/403")
	    .and()
	    .cors().and().csrf().disable();
	  
	  http.authenticationProvider(ssrsDaoAuthenticationProvider());
	  return http.build();
	}    
	
}