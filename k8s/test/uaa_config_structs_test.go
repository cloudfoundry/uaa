package k8s_test

type UaaConfig struct {
	Issuer      Issuer     `yaml:"issuer"`
	Encryption  Encryption `yaml:"encryption"`
	Login       Login      `yaml:"login"`
	LoginSecret string     `yaml:"LOGIN_SECRET"`
	Jwt         Jwt        `yaml:"jwt"`
	Database    Database   `yaml:"database"`
}

type Issuer struct {
	Uri string `yaml:"uri"`
}

type Encryption struct {
	ActiveKeyLabel string `yaml:"active_key_label"`
	EncryptionKeys []struct {
		Label      string `yaml:"label"`
		Passphrase string `yaml:"passphrase"`
	} `yaml:"encryption_keys"`
}

type Jwt struct {
	Token struct {
		SigningKey string `yaml:"signing-key"`
	} `yaml:"token"`
}

type Login struct {
	ServiceProviderKey         string `yaml:"serviceProviderKey"`
	ServiceProviderKeyPassword string `yaml:"serviceProviderKeyPassword"`
	ServiceProviderCertificate string `yaml:"serviceProviderKeyCertificate"`
}

type Database struct {
	MaxActive        int    `yaml:"maxactive"`
	MaxIdle          int    `yaml:"maxidle"`
	MinIdle          int    `yaml:"minidle"`
	RemoveAbandoned  bool   `yaml:"removeabandoned"`
	LogAbandoned     bool   `yaml:"logabandoned"`
	AbandonedTimeout int    `yaml:"abandonedtimeout"`
	Username         string `yaml:"username"`
	Password         string `yaml:"password"`
}
