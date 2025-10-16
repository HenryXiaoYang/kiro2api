package auth

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/types"
)

// AuthService 认证服务（推荐使用依赖注入方式）
type AuthService struct {
	tokenManager *TokenManager
	configs      []AuthConfig
}

// NewAuthService 创建新的认证服务（推荐使用此方法而不是全局函数）
func NewAuthService() (*AuthService, error) {
	logger.Info("创建AuthService实例")

	// 加载配置
	configs, err := loadConfigs()
	if err != nil {
		// 尝试从CSV加载
		if csvConfigs, csvErr := LoadAccountsFromCSV("accounts.csv"); csvErr == nil && len(csvConfigs) > 0 {
			configs = csvConfigs
			logger.Info("从CSV加载账号", logger.Int("数量", len(csvConfigs)))
		} else {
			return nil, fmt.Errorf("加载配置失败: %w", err)
		}
	} else {
		// 从CSV加载额外账号
		if csvConfigs, csvErr := LoadAccountsFromCSV("accounts.csv"); csvErr == nil {
			configs = append(configs, csvConfigs...)
			logger.Info("从CSV加载额外账号", logger.Int("数量", len(csvConfigs)))
		}
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("未找到有效的token配置")
	}

	// 创建token管理器
	tokenManager := NewTokenManager(configs)

	// 预热第一个可用token
	_, warmupErr := tokenManager.getBestToken()
	if warmupErr != nil {
		logger.Warn("token预热失败", logger.Err(warmupErr))
	}

	logger.Info("AuthService创建完成", logger.Int("config_count", len(configs)))

	return &AuthService{
		tokenManager: tokenManager,
		configs:      configs,
	}, nil
}

// GetToken 获取可用的token
func (as *AuthService) GetToken() (types.TokenInfo, error) {
	if as.tokenManager == nil {
		return types.TokenInfo{}, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.getBestToken()
}

// GetTokenManager 获取底层的TokenManager（用于高级操作）
func (as *AuthService) GetTokenManager() *TokenManager {
	return as.tokenManager
}

// GetConfigs 获取认证配置
func (as *AuthService) GetConfigs() []AuthConfig {
	return as.configs
}
