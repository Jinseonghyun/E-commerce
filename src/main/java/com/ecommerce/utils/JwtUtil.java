package com.ecommerce.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    /**
     * Claims 는 JWT (JSON Web Token) 라이브러리에서 제공하는 인터페이스
     */

//    public static final String SECRET = "123456789";   보안을 위헤 설정파일 사용
    @Value("${jwt.secret}")
    private String secret;

    /** generateToken
     * 사용자 이름을 받아 JWT를 생성합니다.
     * 빈 claims 맵을 생성하고 createToken 메서드를 호출
     * Claims는 JWT에 포함된 정보의 조각
     */
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    /** createToken
     * JWT를 실제로 생성하는 메서드입니다.
     * Jwts.builder()를 사용하여 토큰을 구성합니다.
     * claims, 주제(사용자 이름), 발행 시간, 만료 시간을 설정합니다.
     * signWith로 토큰에 서명합니다. (HS256 알고리즘 사용)
     * 토큰의 만료 시간은 현재 시간으로부터 30분 후로 설정
     *
     *
     * // 30분을 밀리초로 변환 //
     * 10000은 10초 (10,000 밀리초)
     * 60을 곱해서 10분
     * 다시 3을 곱해서 30분
     */
    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +  10000  *  60 *  30)) // 현재 시간(밀리초)
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    /** getSignKey
     * 서명에 사용할 키를 생성합니다.
     * SECRET을 Base64 디코딩하여 바이트 배열로 변환한 후, HMAC-SHA 키를 생성
     */
    private Key getSignKey() {
        byte[] keybytes = Decoders.BASE64.decode(secret); //  Base64로 인코딩된 SECRET을 디코드
        return Keys.hmacShaKeyFor(keybytes); // HMAC-SHA 알고리즘용 키를 생성
    }

    // 토큰에서 사용자 이름(주제)을 추출
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // 토큰에서 사용자 이름(주제)을 추출 , Claims::getSubject는 메서드 참조로, Claims 객체의 getSubject 메서드를 호
    }

    /**
     * 제네릭 메서드로, 토큰에서 특정 클레임을 추출합니다.
     * Function<Claims, T> 타입의 함수를 인자로 받아 유연하게 클레임을 추출
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { // Function<Claims, T> Claims를 입력받아 T 타입을 반환하는 함수
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // claimsResolver.apply(claims)는 전달받은 함수를 claims에 적용
    }

    /**
     * 토큰에서 모든 클레임을 추출합니다.
     * Jwts.parserBuilder()를 사용하여 토큰을 파싱
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()// Jwts.parserBuilder(): JWT 파서를 생성
                .setSigningKey(getSignKey()) // setSigningKey(getSignKey()): 서명 검증을 위한 키를 설정
                .build()
                .parseClaimsJws(token) // parseClaimsJws(token): 토큰을 파싱하고 서명을 검증
                .getBody(); // 파싱된 토큰의 본문(클레임)을 반환
    }

    /** 토큰이 만료되었는지 확인
     * 토큰의 만료 시간을 현재 시간과 비교합니다.
     * before(): 만료 시간이 현재 시간보다 이전이면 true를 반환
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 토큰의 만료 시간을 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration); // Claims::getExpiration은 Claims 객체의 getExpiration 메서드를 호출
    }

    /** validateToken
     * 토큰의 유효성을 검증합니다.
     * 토큰에서 추출한 사용자 이름과 UserDetails의 사용자 이름을 비교합니다.
     * 토큰이 만료되지 않았는지 확인
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
