package com.ecommerce.repository;

import com.ecommerce.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> { // JpaRepository 인터페이스를 상속

    /** 사용자 정의 쿼리 메서드 : Spring Data JPA가 메서드 이름을 분석하여 자동으로 쿼리를 생성합니다.
     * Optional<User>: Java 8부터 도입된 Optional 타입을 사용합니다. 이는 null 처리를 보다 안전하게 할 수 있다.
     */
    Optional<User> findFirstByEmail(String email);
}
