package auth

import (
	"fmt"
	"kiro2api/config"
	"kiro2api/logger"
	"kiro2api/types"
	"sync"
	"time"
)

// TokenManager 简化的token管理器
type TokenManager struct {
	cache        *SimpleTokenCache
	configs      []AuthConfig
	mutex        sync.RWMutex
	lastRefresh  time.Time
	configOrder  []string        // 配置顺序
	currentIndex int             // 当前使用的token索引
	exhausted    map[string]bool // 已耗尽的token记录
}

// SimpleTokenCache 简化的token缓存（纯数据结构，无锁）
// 所有并发访问由 TokenManager.mutex 统一管理
type SimpleTokenCache struct {
	tokens map[string]*CachedToken
	ttl    time.Duration
}

// CachedToken 缓存的token信息
type CachedToken struct {
	Token     types.TokenInfo
	UsageInfo *types.UsageLimits
	CachedAt  time.Time
	LastUsed  time.Time
	Available float64
}

// NewSimpleTokenCache 创建简单的token缓存
func NewSimpleTokenCache(ttl time.Duration) *SimpleTokenCache {
	return &SimpleTokenCache{
		tokens: make(map[string]*CachedToken),
		ttl:    ttl,
	}
}

// NewTokenManager 创建新的token管理器
func NewTokenManager(configs []AuthConfig) *TokenManager {
	// 生成配置顺序
	configOrder := generateConfigOrder(configs)

	logger.Info("TokenManager初始化（顺序选择策略）",
		logger.Int("config_count", len(configs)),
		logger.Int("config_order_count", len(configOrder)))

	return &TokenManager{
		cache:        NewSimpleTokenCache(config.TokenCacheTTL),
		configs:      configs,
		configOrder:  configOrder,
		currentIndex: 0,
		exhausted:    make(map[string]bool),
	}
}

// getBestToken 获取最优可用token
// 统一锁管理：所有操作在单一锁保护下完成，避免多次加锁/解锁
func (tm *TokenManager) getBestToken() (types.TokenInfo, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// 选择最优token（内部方法，不加锁）
	bestToken := tm.selectBestTokenUnlocked()
	if bestToken == nil {
		return types.TokenInfo{}, fmt.Errorf("没有可用的token")
	}

	// 更新最后使用时间（在锁内，安全）
	bestToken.LastUsed = time.Now()
	if bestToken.Available > 0 {
		bestToken.Available--
	}

	return bestToken.Token, nil
}

// selectBestTokenUnlocked 按配置顺序选择下一个可用token
// 内部方法：调用者必须持有 tm.mutex
// 重构说明：从selectBestToken改为Unlocked后缀，明确锁约定
func (tm *TokenManager) selectBestTokenUnlocked() *CachedToken {
	// 调用者已持有 tm.mutex，无需额外加锁

	// 如果没有配置顺序，降级到按map遍历顺序
	if len(tm.configOrder) == 0 {
		for key, cached := range tm.cache.tokens {
			if time.Since(cached.CachedAt) <= tm.cache.ttl && cached.IsUsable() {
				logger.Debug("顺序策略选择token（无顺序配置）",
					logger.String("selected_key", key),
					logger.Float64("available_count", cached.Available))
				return cached
			}
		}
		return nil
	}

	// 从当前索引开始，找到第一个可用的token
	for attempts := 0; attempts < len(tm.configOrder); attempts++ {
		currentKey := tm.configOrder[tm.currentIndex]

		// 检查这个token是否存在且可用
		if cached, exists := tm.cache.tokens[currentKey]; exists {
			// 检查token是否过期
			if time.Since(cached.CachedAt) > tm.cache.ttl {
				// 刷新这个token
				if err := tm.refreshSingleTokenByIndex(tm.currentIndex); err != nil {
					logger.Warn("刷新token失败", logger.String("key", currentKey), logger.Err(err))
					tm.exhausted[currentKey] = true
					tm.currentIndex = (tm.currentIndex + 1) % len(tm.configOrder)
					continue
				}
				cached = tm.cache.tokens[currentKey]
			}

			// 检查token是否可用
			if cached.IsUsable() {
				logger.Debug("顺序策略选择token",
					logger.String("selected_key", currentKey),
					logger.Int("index", tm.currentIndex),
					logger.Float64("available_count", cached.Available))
				return cached
			}
		} else {
			// token不存在，刷新它
			if err := tm.refreshSingleTokenByIndex(tm.currentIndex); err != nil {
				logger.Warn("刷新token失败", logger.String("key", currentKey), logger.Err(err))
				tm.exhausted[currentKey] = true
				tm.currentIndex = (tm.currentIndex + 1) % len(tm.configOrder)
				continue
			}
			if cached, exists := tm.cache.tokens[currentKey]; exists && cached.IsUsable() {
				logger.Debug("顺序策略选择token",
					logger.String("selected_key", currentKey),
					logger.Int("index", tm.currentIndex),
					logger.Float64("available_count", cached.Available))
				return cached
			}
		}

		// 标记当前token为已耗尽，移动到下一个
		tm.exhausted[currentKey] = true
		tm.currentIndex = (tm.currentIndex + 1) % len(tm.configOrder)

		logger.Debug("token不可用，切换到下一个",
			logger.String("exhausted_key", currentKey),
			logger.Int("next_index", tm.currentIndex))
	}

	// 所有token都不可用
	logger.Warn("所有token都不可用",
		logger.Int("total_count", len(tm.configOrder)),
		logger.Int("exhausted_count", len(tm.exhausted)))

	return nil
}

// refreshSingleTokenByIndex 刷新指定索引的token
// 内部方法：调用者必须持有 tm.mutex
func (tm *TokenManager) refreshSingleTokenByIndex(index int) error {
	if index >= len(tm.configs) {
		return fmt.Errorf("索引超出范围")
	}

	cfg := tm.configs[index]
	if cfg.Disabled {
		return fmt.Errorf("token已禁用")
	}

	// 刷新token
	token, err := tm.refreshSingleToken(cfg)
	if err != nil {
		return fmt.Errorf("刷新token失败: %w", err)
	}

	// 检查使用限制
	var usageInfo *types.UsageLimits
	var available float64

	checker := NewUsageLimitsChecker()
	if usage, checkErr := checker.CheckUsageLimits(token); checkErr == nil {
		usageInfo = usage
		available = CalculateAvailableCount(usage)
	} else {
		logger.Warn("检查使用限制失败", logger.Err(checkErr))
	}

	// 更新缓存
	cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, index)
	tm.cache.tokens[cacheKey] = &CachedToken{
		Token:     token,
		UsageInfo: usageInfo,
		CachedAt:  time.Now(),
		Available: available,
	}

	logger.Debug("token缓存更新",
		logger.String("cache_key", cacheKey),
		logger.Float64("available", available))

	return nil
}

// refreshCacheUnlocked 刷新所有token缓存
// 内部方法：调用者必须持有 tm.mutex
func (tm *TokenManager) refreshCacheUnlocked() error {
	logger.Debug("开始刷新所有token缓存")

	for i := range tm.configs {
		if err := tm.refreshSingleTokenByIndex(i); err != nil {
			logger.Warn("刷新token失败", logger.Int("index", i), logger.Err(err))
		}
	}

	tm.lastRefresh = time.Now()
	return nil
}

// IsUsable 检查缓存的token是否可用
func (ct *CachedToken) IsUsable() bool {
	// 检查token是否过期
	if time.Now().After(ct.Token.ExpiresAt) {
		return false
	}

	// 检查可用次数
	return ct.Available > 0
}

// *** 已删除 set 和 updateLastUsed 方法 ***
// SimpleTokenCache 现在是纯数据结构，所有访问由 TokenManager.mutex 保护
// set 操作：直接通过 tm.cache.tokens[key] = value 完成
// updateLastUsed 操作：已合并到 getBestToken 方法中

// CalculateAvailableCount 计算可用次数 (基于CREDIT资源类型，返回浮点精度)
func CalculateAvailableCount(usage *types.UsageLimits) float64 {
	for _, breakdown := range usage.UsageBreakdownList {
		if breakdown.ResourceType == "CREDIT" {
			var totalAvailable float64

			// 优先使用免费试用额度 (如果存在且处于ACTIVE状态)
			if breakdown.FreeTrialInfo != nil && breakdown.FreeTrialInfo.FreeTrialStatus == "ACTIVE" {
				freeTrialAvailable := breakdown.FreeTrialInfo.UsageLimitWithPrecision - breakdown.FreeTrialInfo.CurrentUsageWithPrecision
				totalAvailable += freeTrialAvailable
			}

			// 加上基础额度
			baseAvailable := breakdown.UsageLimitWithPrecision - breakdown.CurrentUsageWithPrecision
			totalAvailable += baseAvailable

			if totalAvailable < 0 {
				return 0.0
			}
			return totalAvailable
		}
	}
	return 0.0
}

// generateConfigOrder 生成token配置的顺序
func generateConfigOrder(configs []AuthConfig) []string {
	var order []string

	for i := range configs {
		// 使用索引生成cache key，与refreshCache中的逻辑保持一致
		cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, i)
		order = append(order, cacheKey)
	}

	logger.Debug("生成配置顺序",
		logger.Int("config_count", len(configs)),
		logger.Any("order", order))

	return order
}
