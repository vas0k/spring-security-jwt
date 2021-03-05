package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.models.AuthenticationResponse;
import io.javabrains.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

}

@RestController
class HelloResource{

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;

	@RequestMapping( {"/hello"} )
	public String hello(){
		return "Hello World!";
	}

	// To actually authenticate a user, use AuthenticationManager
	// Once authentication is successful, create a JWT token, and return it.
	// This endpoint will ask for username and password, by default, which is not necessary. To work around this, -
	// - The SecurityConfigurer should be tweaked to accept any request only to this endpoint, and require authentication to other endpoints.
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		try{
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		}
		catch(BadCredentialsException e){
			throw new Exception("Incorrect credentials!!!!!");
		}

		final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		final String jwt =  jwtUtil.generateToken(userDetails);
		// Returns a 200 OK
		return ResponseEntity.ok(new AuthenticationResponse(jwt));

	}
}