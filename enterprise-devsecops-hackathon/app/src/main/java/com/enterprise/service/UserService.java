package com.enterprise.service;

import com.enterprise.model.User;
import com.enterprise.util.CryptoUtil;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
public class UserService {

    private static final Logger logger = Logger.getLogger(UserService.class.getName());

    public String registerUser(User user) throws Exception {

        // Weak crypto (MD5)
        String hashed = CryptoUtil.hashPassword(user.getPassword());

        // Sensitive logging (LOW severity issue)
        logger.info("Registering user with password: " + user.getPassword());

        return "User Registered with hash: " + hashed;
    }
}