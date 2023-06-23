package com.authentication.cleveryauthentication.web;

import com.authentication.cleveryauthentication.document.User;
import com.authentication.cleveryauthentication.dto.UserDTO;
import com.authentication.cleveryauthentication.repository.UserRepository;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/clevery/users")
public class UserController {
    @Autowired
    UserRepository userRepository;

    @GetMapping("/{id}")
    @PreAuthorize("#user.id == #id")
    public ResponseEntity user(@AuthenticationPrincipal User user, @PathVariable String id) {
        ObjectId objectId = new ObjectId(id);
        return ResponseEntity.ok(UserDTO.from(userRepository.findById(String.valueOf(objectId)).orElseThrow()));
    }

}