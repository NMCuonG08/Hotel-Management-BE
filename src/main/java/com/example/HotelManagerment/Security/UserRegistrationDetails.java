package com.example.HotelManagerment.Security;

import com.example.HotelManagerment.User.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.*;
import java.util.stream.Collectors;

@Data
public class UserRegistrationDetails implements UserDetails {

    private String email;
    private String passWord;
    private boolean isEnable;
    private List<GrantedAuthority> authorities;

    public UserRegistrationDetails(User user) {
        this.email = user.getEmail();
        this.passWord = user.getPassword();
        this.isEnable = user.isEnabled();
        this.authorities = Arrays.stream(user.getRole()
                .split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }


    @Override
    public String getPassword() {
        return passWord;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isEnable;
    }
}
