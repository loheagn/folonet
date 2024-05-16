package main

type ServerUnit struct {
	Name          string `gorm:"primaryKey"`
	Deployment    string
	Service       string
	Namespace     string
	IP            string
	LocalEndpoint string
}

type IPPair struct {
	IP            string `gorm:"primaryKey"`
	Checkpoint    string `gorm:"default:''"`
	LocalEndpoint string `gorm:"default:''"`
}
