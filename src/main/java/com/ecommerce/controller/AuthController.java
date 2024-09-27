package com.ecommerce.controller;

import com.ecommerce.dto.AuthenticationRequest;
import com.ecommerce.entity.User;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final UserDetailsService userDetailsService;

    private final UserRepository userRepository;

    private final JwtUtil jwtUtil;

    /**
     * JWT 토큰 관련 상수들을 정의
     */
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) { // authenticationRequest 객체를 요청 본문으로 받습니다.

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Incorrect username or password.");
        }

        /**
         * 인증된 사용자의 상세 정보를 로드합니다.
         * 이메일로 사용자 정보를 데이터베이스에서 조회합니다.
         */
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        Optional<User> optionalUser = userRepository.findFirstByEmail(userDetails.getUsername());

        /**
         * 사용자 이름으로 JWT 토큰을 생성
         */
        final String jwt = jwtUtil.generateToken(userDetails.getUsername());

        /**
         * 사용자가 존재하면 응답 본문에 사용자 ID와 역할을 포함시킵니다.
         * 응답 헤더에 JWT 토큰을 추가합니다.
         * ResponseEntity를 사용하여 응답을 구성합니다.
         */
        if (optionalUser.isPresent()) {
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("userId", optionalUser.get().getId());
            responseBody.put("role", optionalUser.get().getRole());

            return ResponseEntity.ok()
                    .header(HEADER_STRING, TOKEN_PREFIX + jwt)
                    .body(responseBody);
        }

        return ResponseEntity.notFound().build(); // 용자를 찾지 못한 경우 404 Not Found 응답을 반환
    }
}
