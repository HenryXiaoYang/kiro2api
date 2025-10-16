package auth

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kiro2api/logger"
)

// AuthConfig 简化的认证配置
type AuthConfig struct {
	AuthType     string `json:"auth"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
}

// 认证方法常量
const (
	AuthMethodSocial = "Social"
	AuthMethodIdC    = "IdC"
)

// loadConfigs 从环境变量加载配置
func loadConfigs() ([]AuthConfig, error) {
	// 检测并警告弃用的环境变量
	deprecatedVars := []string{
		"REFRESH_TOKEN",
		"AWS_REFRESHTOKEN",
		"IDC_REFRESH_TOKEN",
		"BULK_REFRESH_TOKENS",
	}

	for _, envVar := range deprecatedVars {
		if os.Getenv(envVar) != "" {
			logger.Warn("检测到已弃用的环境变量",
				logger.String("变量名", envVar),
				logger.String("迁移说明", "请迁移到KIRO_AUTH_TOKEN的JSON格式"))
			logger.Warn("迁移示例",
				logger.String("新格式", `KIRO_AUTH_TOKEN='[{"auth":"Social","refreshToken":"your_token"}]'`))
		}
	}

	// 只支持KIRO_AUTH_TOKEN的JSON格式（支持文件路径或JSON字符串）
	jsonData := os.Getenv("KIRO_AUTH_TOKEN")
	if jsonData == "" {
		return nil, fmt.Errorf("未找到KIRO_AUTH_TOKEN环境变量\n" +
			"请设置: KIRO_AUTH_TOKEN='[{\"auth\":\"Social\",\"refreshToken\":\"your_token\"}]'\n" +
			"或设置为配置文件路径: KIRO_AUTH_TOKEN=/path/to/config.json\n" +
			"支持的认证方式: Social, IdC\n" +
			"详细配置请参考: .env.example")
	}

	// 优先尝试从文件加载，失败后再作为JSON字符串处理
	var configData string
	if fileInfo, err := os.Stat(jsonData); err == nil && !fileInfo.IsDir() {
		// 是文件，读取文件内容
		content, err := os.ReadFile(jsonData)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w\n配置文件路径: %s", err, jsonData)
		}
		configData = string(content)
		logger.Info("从文件加载认证配置", logger.String("文件路径", jsonData))
	} else {
		// 不是文件或文件不存在，作为JSON字符串处理
		configData = jsonData
		logger.Debug("从环境变量加载JSON配置")
	}

	// 解析JSON配置
	configs, err := parseJSONConfig(configData)
	if err != nil {
		return nil, fmt.Errorf("解析KIRO_AUTH_TOKEN失败: %w\n"+
			"请检查JSON格式是否正确\n"+
			"示例: KIRO_AUTH_TOKEN='[{\"auth\":\"Social\",\"refreshToken\":\"token1\"}]'", err)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("KIRO_AUTH_TOKEN配置为空，请至少提供一个有效的认证配置")
	}

	validConfigs := processConfigs(configs)
	if len(validConfigs) == 0 {
		return nil, fmt.Errorf("没有有效的认证配置\n" +
			"请检查: \n" +
			"1. Social认证需要refreshToken字段\n" +
			"2. IdC认证需要refreshToken、clientId、clientSecret字段")
	}

	logger.Info("成功加载认证配置",
		logger.Int("总配置数", len(configs)),
		logger.Int("有效配置数", len(validConfigs)))

	return validConfigs, nil
}

// GetConfigs 公开的配置获取函数，供其他包调用
func GetConfigs() ([]AuthConfig, error) {
	return loadConfigs()
}

// parseJSONConfig 解析JSON配置字符串
func parseJSONConfig(jsonData string) ([]AuthConfig, error) {
	var configs []AuthConfig

	// 尝试解析为数组
	if err := json.Unmarshal([]byte(jsonData), &configs); err != nil {
		// 尝试解析为单个对象
		var single AuthConfig
		if err := json.Unmarshal([]byte(jsonData), &single); err != nil {
			return nil, fmt.Errorf("JSON格式无效: %w", err)
		}
		configs = []AuthConfig{single}
	}

	return configs, nil
}

// processConfigs 处理和验证配置
func processConfigs(configs []AuthConfig) []AuthConfig {
	var validConfigs []AuthConfig

	for i, config := range configs {
		// 验证必要字段
		if config.RefreshToken == "" {
			continue
		}

		// 设置默认认证类型
		if config.AuthType == "" {
			config.AuthType = AuthMethodSocial
		}

		// 验证IdC认证的必要字段
		if config.AuthType == AuthMethodIdC {
			if config.ClientID == "" || config.ClientSecret == "" {
				continue
			}
		}

		// 跳过禁用的配置
		if config.Disabled {
			continue
		}

		validConfigs = append(validConfigs, config)
		_ = i // 避免未使用变量警告
	}

	return validConfigs
}

// LoadAccountsFromCSV 从CSV文件加载账号配置
func LoadAccountsFromCSV(filePath string) ([]AuthConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开CSV文件失败: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("读取CSV文件失败: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV文件为空或缺少数据行")
	}

	var configs []AuthConfig
	for i, record := range records[1:] {
		if len(record) < 4 {
			logger.Warn("跳过无效的CSV行", logger.Int("行号", i+2))
			continue
		}

		enabled := strings.ToLower(strings.TrimSpace(record[0])) == "true"
		if !enabled {
			continue
		}

		configs = append(configs, AuthConfig{
			AuthType:     AuthMethodIdC,
			RefreshToken: strings.TrimSpace(record[1]),
			ClientID:     strings.TrimSpace(record[2]),
			ClientSecret: strings.TrimSpace(record[3]),
		})
	}

	logger.Info("从CSV加载账号", logger.Int("总数", len(configs)))
	return configs, nil
}

// AddAccountsFromCSV 从CSV文件添加账号到TokenManager
func (tm *TokenManager) AddAccountsFromCSV(filePath string) error {
	newConfigs, err := LoadAccountsFromCSV(filePath)
	if err != nil {
		return err
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tm.configs = append(tm.configs, newConfigs...)
	tm.configOrder = generateConfigOrder(tm.configs)

	logger.Info("添加CSV账号到TokenManager",
		logger.Int("新增数量", len(newConfigs)),
		logger.Int("总配置数", len(tm.configs)))

	return tm.refreshCacheUnlocked()
}
