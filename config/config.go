package config

import (
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigFile is the default configuration file.
	DefaultConfigFile = "./config/config.yaml"
	// DefaultHost is the default host
	DefaultHost = "localhost"
	// DefaultPort is the default port to run the server on.
	DefaultPort = "8080"
	// DefaultPrivateKey is the default private key to use for signing tokens.
	DefaultPrivateKey = "./config/private.pem"
	// DefaultPublicKey is the default public key to use for verifying tokens.
	DefaultPublicKey = "./config/public.pem"
)

const (
	// AvailableDatabaseDrivers is a list of available database drivers.
	AvailableDatabaseDrivers = "postgres,sqlite"
)

const (
	// DefaultDBDriver is the default database driver.
	DefaultDBDriver = "sqlite"
	// DefaultDBHost is the default database host.
	DefaultDBHost = ""
	// DefaultDBPort is the default database port.
	DefaultDBPort = ""
	// DefaultDBUser is the default database user.
	DefaultDBUser = ""
	// DefaultDBPassword is the default database password.
	DefaultDBPassword = ""
	// DefaultDBName is the default database name.
	DefaultDBName = "./config/sqlite.db"
)

type (
	Server struct {
		Host       string `yaml:"host,omitempty" json:"host,omitempty" env:"HOST"`
		Port       string `yaml:"port,omitempty" json:"port,omitempty" env:"PORT"`
		PrivateKey string `yaml:"private_key" json:"private_key" env:"PRIVATE_KEY"`
		PublicKey  string `yaml:"public_key" json:"public_key" env:"PUBLIC_KEY"`
	}
	Database struct {
		Type     string `yaml:"type" json:"type" env:"DB_TYPE"`
		Host     string `yaml:"host,omitempty" json:"host,omitempty" env:"DB_HOST"`
		Port     string `yaml:"port,omitempty" json:"port,omitempty" env:"DB_PORT"`
		Username string `yaml:"user,omitempty" json:"user,omitempty" env:"DB_USER"`
		Password string `yaml:"pass,omitempty" json:"pass,omitempty" env:"DB_PASS"`
		Name     string `yaml:"name,omitempty" json:"name,omitempty" env:"DB_NAME"`
	}
)

type Config struct {
	Server   Server   `yaml:"server" json:"server"`
	Database Database `yaml:"database" json:"database"`
}

// Load loads the configuration from a file.
func (cfg *Config) Load(file string) error {
	if file == "" {
		file = DefaultConfigFile
	}
	if !filepath.IsAbs(file) {
		// Get the absolute path of the configuration file.
		file, _ = filepath.Abs(file)
	}
	// Read file content
	content, err := os.ReadFile(file)
	if err != nil {
		log.Fatalln("unable to read configuration file:", err)
		return err
	}
	// Unmarshal from YAML
	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		log.Fatalln("unable to read configuration file:", err)
		return err
	}
	executablePath, err := GetExecutablePath()
	if err != nil {
		log.Println(err)
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = DefaultHost
	}
	if cfg.Server.Port == "" {
		cfg.Server.Port = DefaultPort
	}
	if cfg.Server.PrivateKey == "" {
		cfg.Server.PrivateKey = filepath.Join(executablePath, DefaultPrivateKey)
	}
	if !filepath.IsAbs(cfg.Server.PrivateKey) {
		cfg.Server.PrivateKey = filepath.Join(executablePath, cfg.Server.PrivateKey)
	}
	if cfg.Server.PublicKey == "" {
		cfg.Server.PublicKey = filepath.Join(executablePath, DefaultPublicKey)
	}
	if !filepath.IsAbs(cfg.Server.PublicKey) {
		cfg.Server.PublicKey = filepath.Join(executablePath, cfg.Server.PublicKey)
	}
	if cfg.Database.Type == "" {
		cfg.Database.Type = DefaultDBDriver
		cfg.Database.Name = filepath.Join(executablePath, DefaultDBName)
	}
	if cfg.Database.Type == "sqlite" {
		if cfg.Database.Name == "" {
			cfg.Database.Name = filepath.Join(executablePath, DefaultDBName)
		}
		if !filepath.IsAbs(cfg.Database.Name) {
			cfg.Database.Name = filepath.Join(executablePath, cfg.Database.Name)
		}
	}

	return nil
}

// RelativePath returns the absolute path of a relative path.
func RelativePath(basedir string, path *string) {
	p := *path
	if len(p) > 0 && p[0] != '/' {
		*path = filepath.Join(basedir, p)
	}
}

// GetExecutablePath returns the absolute path of the executable
func GetExecutablePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	exPath := filepath.Dir(ex)
	return exPath, nil
}

// NewDefault returns a new default configuration struct.
func NewDefault() *Config {
	executablePath, err := GetExecutablePath()
	if err != nil {
		log.Println(err)
	}
	cfg := &Config{
		Server: Server{
			Host:       DefaultHost,
			Port:       DefaultPort,
			PrivateKey: filepath.Join(executablePath, DefaultPrivateKey),
			PublicKey:  filepath.Join(executablePath, DefaultPublicKey),
		},
		Database: Database{
			Type:     DefaultDBDriver,
			Host:     DefaultDBHost,
			Port:     DefaultDBPort,
			Username: DefaultDBUser,
			Password: DefaultDBPassword,
			Name:     filepath.Join(executablePath, DefaultDBName),
		},
	}
	return cfg
}

// GetConfig returns the configuration struct.
func GetConfig() *Config {
	config := &Config{}
	executablePath, err := GetExecutablePath()
	if err != nil {
		log.Println(err)
	}

	var configFile string
	_, present := os.LookupEnv("CONFIG_FILE")
	if present {
		configFile = os.Getenv("CONFIG_FILE")
	}

	// Load the configuration from the file.
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		config.Load(DefaultConfigFile)
	} else if _, err := os.Stat(filepath.Join(executablePath, DefaultConfigFile)); err == nil {
		config.Load(filepath.Join(executablePath, DefaultConfigFile))
	} else if _, err := os.Stat(filepath.Join(executablePath, "config.yaml")); err == nil {
		config.Load(filepath.Join(executablePath, "config.yaml"))
	} else if _, err := os.Stat(configFile); err == nil {
		config.Load(configFile)
	} else {
		// Create a new default configuration.
		config = NewDefault()
	}

	// Check for config in environment variables.
	_, present = os.LookupEnv("HOST")
	if present {
		config.Server.Host = os.Getenv("HOST")
	}
	_, present = os.LookupEnv("PORT")
	if present {
		config.Server.Port = os.Getenv("PORT")
	}
	_, present = os.LookupEnv("PRIVATE_KEY")
	if present {
		config.Server.PrivateKey = os.Getenv("PRIVATE_KEY")
		if !filepath.IsAbs(config.Server.PrivateKey) && config.Server.PrivateKey != "" {
			config.Server.PrivateKey = filepath.Join(executablePath, config.Server.PrivateKey)
		}
	}
	_, present = os.LookupEnv("PUBLIC_KEY")
	if present {
		config.Server.PublicKey = os.Getenv("PUBLIC_KEY")
		if !filepath.IsAbs(config.Server.PublicKey) && config.Server.PublicKey != "" {
			config.Server.PublicKey = filepath.Join(executablePath, config.Server.PublicKey)
		}
	}
	_, present = os.LookupEnv("DB_TYPE")
	if present {
		config.Database.Type = os.Getenv("DB_TYPE")
		if config.Database.Type == "sqlite" {
			_, present = os.LookupEnv("DB_NAME")
			if !present {
				config.Database.Name = filepath.Join(executablePath, DefaultDBName)
			} else {
				config.Database.Name = os.Getenv("DB_NAME")
				if !filepath.IsAbs(config.Database.Name) && config.Database.Name != "" {
					config.Database.Name = filepath.Join(executablePath, config.Database.Name)
				}
			}
		}
	}
	_, present = os.LookupEnv("DB_HOST")
	if present {
		config.Database.Host = os.Getenv("DB_HOST")
	}
	_, present = os.LookupEnv("DB_PORT")
	if present {
		config.Database.Port = os.Getenv("DB_PORT")
	}
	_, present = os.LookupEnv("DB_USER")
	if present {
		config.Database.Username = os.Getenv("DB_USER")
	}
	_, present = os.LookupEnv("DB_PASSWORD")
	if present {
		config.Database.Password = os.Getenv("DB_PASSWORD")
	}
	_, present = os.LookupEnv("DB_NAME")
	if present {
		config.Database.Name = os.Getenv("DB_NAME")
	}

	return config
}
