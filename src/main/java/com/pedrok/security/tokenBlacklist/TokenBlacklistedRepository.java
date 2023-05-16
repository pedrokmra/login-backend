package com.pedrok.security.tokenBlacklist;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenBlacklistedRepository extends JpaRepository<TokenBlacklisted, Long> {
    boolean existsByTokenValue(String tokenValue);
}
