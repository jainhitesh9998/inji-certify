/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;

@ConditionalOnProperty(value = "spring.cache.type", havingValue = "simple")
@Configuration
@Slf4j
public class SimpleCacheConfig extends CachingConfigurerSupport {

    /** What a cache without an expiry entry lives for. Short on purpose (a leaked entry is cheap), which is why a
     *  silently inherited default is a bug for a cache whose entries are meant to outlive it (the pre-authorized code
     *  cache holds offers that advertise {@code expires_in} up to an hour; F-21 review round 1). */
    private static final int DEFAULT_EXPIRE_IN_SECONDS = 60;

    @Value("${mosip.certify.cache.names}")
    private List<String> cacheNames;

    @Value("#{${mosip.certify.cache.size}}")
    private Map<String, Integer> cacheMaxSize;

    @Value("#{${mosip.certify.cache.expire-in-seconds}}")
    private Map<String, Integer> cacheExpireInSeconds;


    @Bean
    @Override
    public CacheManager cacheManager() {
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        List<Cache> caches = new ArrayList<>();
        for(String name : cacheNames) {
            caches.add(buildMapCache(name));
        }
        cacheManager.setCaches(caches);
        return cacheManager;
    }

    private ConcurrentMapCache buildMapCache(String name) {
        if (!cacheExpireInSeconds.containsKey(name)) {
            log.warn("Cache '{}' has no mosip.certify.cache.expire-in-seconds entry: it lives for the {} s default, not for "
                    + "as long as its entries are meant to. Add it to every profile's map.", name, DEFAULT_EXPIRE_IN_SECONDS);
        }
        return new ConcurrentMapCache(name,
                CacheBuilder.newBuilder()
                        .expireAfterWrite(cacheExpireInSeconds.getOrDefault(name, DEFAULT_EXPIRE_IN_SECONDS), TimeUnit.SECONDS)
                        .maximumSize(cacheMaxSize.getOrDefault(name, 100))
                        .build()
                        .asMap(), true);
    }
}
