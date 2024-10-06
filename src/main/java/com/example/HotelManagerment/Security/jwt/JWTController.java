package com.example.HotelManagerment.Security.jwt;

import com.example.HotelManagerment.Security.UserRegistrationDetailsService;
import com.example.HotelManagerment.User.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@CrossOrigin("http://localhost:5173")
@RestController
@RequiredArgsConstructor
@RequestMapping("/authentication")
public class JWTController {

    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserRegistrationDetailsService userRegistrationDetailsService;

    @PostMapping
    public String getTokenForAuthentication(@RequestBody JWTAuthenticationRequest authRequest){
        Authentication authentication= authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword()));
        if(authentication.isAuthenticated()){
            return jwtService.getGeneratedToken(authRequest.getEmail());
        }
        else {
            throw  new UsernameNotFoundException("Invalid User credentials");
        }
    }
    @GetMapping("/check")
    public ResponseEntity<UserDetails> check(@RequestParam String email){
        UserDetails userDetails = userRegistrationDetailsService.loadUserByUsername(email);
        return ResponseEntity.ok(userDetails);
    }

}
