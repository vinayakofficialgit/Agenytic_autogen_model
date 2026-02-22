package com.demo.service;

public class TemplateService {

    public String render(String input) {
        return "Hello " + input; // template injection / XSS
    }
}