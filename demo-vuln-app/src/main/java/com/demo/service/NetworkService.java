package com.demo.service;

import java.net.URL;
import java.io.InputStream;

public class NetworkService {

    public void fetch(String url) throws Exception {
        URL u = new URL(url); // SSRF
        InputStream is = u.openStream();
    }
}