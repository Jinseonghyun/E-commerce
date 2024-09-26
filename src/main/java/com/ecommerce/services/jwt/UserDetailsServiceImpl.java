package com.ecommerce.services.jwt;

import com.ecommerce.entity.User;
import com.ecommerce.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService { //  Spring Security의 UserDetailsService 인터페이스를 구현합니다. 이 인터페이스는 사용자 정보를 로드하는 데 사용

    @Autowired
    private UserRepository userRepository; // 사용자 정보를 데이터베이스에서 조회하는 데 사용되는 리포지토리 인터페이스

    /**
     * loadUserByUsername: UserDetailsService 인터페이스의 메서드를 구현합니다.
     * 이 메서드는 주어진 사용자 이름(여기서는 이메일)으로 사용자 정보를 로드
     */

    /**
     * 사용자가 존재하면 Spring Security의 User 객체를 생성하여 반환합니다.
     * 첫 번째 인자: 사용자의 이메일 (username으로 사용)
     * 두 번째 인자: 사용자의 비밀번호
     * 세 번째 인자: 사용자의 권한 목록. 여기서는 빈 ArrayList를 전달하여 권한이 없음을 나타냅니다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findFirstByEmail(username);  // userRepository를 사용하여 데이터베이스에서 이메일(username)로 사용자를 조회, Optional<User>를 반환하여 사용자가 존재하지 않을 수 있음을 나타냄
        if (optionalUser.isEmpty()) throw new UsernameNotFoundException("username not found", null); // 사용자가 존재하지 않으면 UsernameNotFoundException을 발생시킵니다. 이는 Spring Security에게 인증 실패를 알리는 방법

        return new org.springframework.security.core.userdetails.User(optionalUser.get().getEmail(), optionalUser.get().getPassword(), new ArrayList<>());
    }
}
