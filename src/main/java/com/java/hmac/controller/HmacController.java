package com.java.hmac.controller;

import com.java.hmac.constants.Constants;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
public class HmacController {

    @RequestMapping(value = "/o/api/users/{userId}", method = RequestMethod.GET, consumes = Constants.CONSUME_APPLICATION_JSON)
    public String getUser(HttpServletResponse response,
                          @PathVariable("userId") String userId) {
        return "Bhanuka " + userId + "OAuth key filter success !";
    }

}
