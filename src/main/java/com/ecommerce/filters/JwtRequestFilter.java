package com.ecommerce.filters;

import com.ecommerce.services.jwt.UserDetailsServiceImpl;
import com.ecommerce.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class  JwtRequestFilter extends OncePerRequestFilter { // OncePerRequestFilter 필터가 요청당 한 번만 실행되도록 보장

    private final UserDetailsServiceImpl userDetailsService; // UserDetailsServiceImpl은 사용자 정보를 로드하는 데 사용
    private final JwtUtil jwtUtil;  // JwtUtil은 JWT 토큰을 처리하는 유틸리티 클래스

    /**
     * doFilterInternal 메서드는 각 HTTP 요청에 대해 실행됩니다.
     * request: 현재 HTTP 요청
     * response: HTTP 응답
     * filterChain: 다음 필터로 요청을 전달하는 데 사용됩니다
     * Authorization 헤더에서 JWT 토큰을 추출합니다.
     * token과 username 변수를 초기화
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) { // Authorization 헤더가 존재하고 "Bearer "로 시작하는지 확인
            token = authHeader.substring(7); // "Bearer " 다음의 문자열(토큰)을 추출
            username = jwtUtil.extractUsername(token); // 토큰에서 사용자 이름을 추출
        }

        if (authHeader != null && SecurityContextHolder.getContext().getAuthentication() == null) { // 인증 헤더가 존재하고, 현재 보안 컨텍스트에 인증 정보가 없는 경우에만 진행
            UserDetails userDetails = userDetailsService.loadUserByUsername(username); // 추출된 사용자 이름으로 사용자 정보를 로드

            if (jwtUtil.validateToken(token, userDetails)) { // 토큰이 유효한지 확인
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null); // 인증 토큰을 생성
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // 인증 토큰에 요청 세부 정보를 설정
                SecurityContextHolder.getContext().setAuthentication(authToken); // 보안 컨텍스트에 인증 정보를 설정
            }
        }

        filterChain.doFilter(request, response); // 필터 체인의 다음 필터로 요청을 전달
    }
}
