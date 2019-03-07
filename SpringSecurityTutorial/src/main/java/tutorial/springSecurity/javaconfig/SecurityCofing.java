package tutorial.springSecurity.javaconfig;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@EnableWebSecurity
public class SecurityCofing extends WebSecurityConfigurerAdapter{
	
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
		.withUser("admin").password("$2a$10$3IT5xuBhUmKokm/JMtVjXem5WoMU4GiOE2SV5Gdaejv4wIEXQNBdW").roles("ADMIN")
		.and()
		.passwordEncoder(new BCryptPasswordEncoder());
	}
	
	
	
	
	
	 @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        http.authorizeRequests().antMatchers("/").hasAnyRole("ADMIN")
	        .and()
	        .formLogin()
	        .and()
	        .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	        .and()
	        .csrf().disable();
	    }
	

}
