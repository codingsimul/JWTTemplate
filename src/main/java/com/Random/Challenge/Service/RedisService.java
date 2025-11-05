package com.docker.jwt.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;

    // 데이터 저장
    public void setValue(String key, String value) {
        redisTemplate.opsForValue().set(key, value);
    }

    // 데이터 저장 (만료시간 포함)
    public void setValue(String key, String value, long duration) {
        redisTemplate.opsForValue().set(key, value, duration, TimeUnit.SECONDS);
    }

    // 데이터 조회
    public String getValue(String key) {
        Object value = redisTemplate.opsForValue().get(key);
        return value != null ? value.toString() : null;
    }

    // 키 삭제
    public Boolean deleteValue(String key) {
        return redisTemplate.delete(key);
    }

    // 만료시간 설정
    public Boolean setExpire(String key, long duration) {
        return redisTemplate.expire(key, duration, TimeUnit.SECONDS);
    }

    // 키 존재 확인
    public Boolean exists(String key) {
        return redisTemplate.hasKey(key);
    }
}
