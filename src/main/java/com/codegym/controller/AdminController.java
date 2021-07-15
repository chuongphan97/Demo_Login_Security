package com.codegym.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AdminController {
    private String getPrincipal() {
        String userName = null;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            userName = ((UserDetails) principal).getUsername();
        } else {
            userName = principal.toString();
        }
        return userName;
    }

    @GetMapping(value = {"/", "/home"})
    public ModelAndView Homepage() {
        ModelAndView modelAndView = new ModelAndView("/home");
        modelAndView.addObject("user", getPrincipal());
        return modelAndView;
    }

    @GetMapping("/admin")
    public ModelAndView adminPage() {
        ModelAndView modelAndView = new ModelAndView("/admin");
        modelAndView.addObject("user", getPrincipal());
        return modelAndView;
    }

    @GetMapping( "/manager")
    public String dbaPage(ModelMap model) {
        model.addAttribute("user", getPrincipal());
        return "/manager";
    }
}
