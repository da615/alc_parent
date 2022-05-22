package com.atguigu.security.security;

import com.atguigu.security.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DefaultPasswordEncoder implements PasswordEncoder {
    DefaultPasswordEncoder(){
        this(-1);
    }

    DefaultPasswordEncoder(int strength){


    }

    //密码加密
    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }

    //进行密码比对
    @Override
    public boolean matches(CharSequence charSequence, String encoderPassword) {
        return encoderPassword. equals(MD5.encrypt(charSequence.toString()));
    }
}
