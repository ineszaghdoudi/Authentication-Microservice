package com.authentication.cleveryauthentication.service;

import com.authentication.cleveryauthentication.document.User;
import com.authentication.cleveryauthentication.dto.TokenDTO;
import com.authentication.cleveryauthentication.repository.UserRepository;import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;
import java.util.Optional;

@Service
public class UserManager implements UserDetailsManager {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDetails user) {
        ((User) user).setPassword(passwordEncoder.encode(user.getPassword())); // Encoding the user's password
        userRepository.save((User) user); //save user
    }


    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        MessageFormat.format("username {0} not found", username)
                )); // Loading a user from the repository by username and throwing an exception if not found
    }


    public boolean checkIfUserLoggedOut(String userId, TokenDTO tokenDTO) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.getId().equals(tokenDTO.getUserId())) {
                user.setLoggedOut(true); // Set the loggedOut flag to true for the user
                userRepository.save(user); // Save the updated user
                return true; // User is logged out
            }
        }
        return false; // User is not logged out
    }




}