package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	endpoint       string
	timeout        int
	verbose        bool
	securityPolicy string
	securityMode   string
	certFile       string
	keyFile        string
)

var rootCmd = &cobra.Command{
	Use:   "edgeo-opcua",
	Short: "OPC UA command line client",
	Long: `A command line interface for OPC UA servers.

Examples:
  edgeo-opcua browse -e opc.tcp://localhost:4840
  edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;i=1"
  edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;i=1" -v 42`,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&endpoint, "endpoint", "e", "opc.tcp://localhost:4840", "OPC UA server endpoint URL")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 5000, "Operation timeout in milliseconds")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&securityPolicy, "security-policy", "s", "None", "Security policy (None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss)")
	rootCmd.PersistentFlags().StringVarP(&securityMode, "security-mode", "m", "None", "Security mode (None, Sign, SignAndEncrypt)")
	rootCmd.PersistentFlags().StringVar(&certFile, "cert", "", "Path to client certificate file (PEM format)")
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Path to client private key file (PEM format)")

	viper.BindPFlag("endpoint", rootCmd.PersistentFlags().Lookup("endpoint"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("security-policy", rootCmd.PersistentFlags().Lookup("security-policy"))
	viper.BindPFlag("security-mode", rootCmd.PersistentFlags().Lookup("security-mode"))

	// Add subcommands
	rootCmd.AddCommand(browseCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(writeCmd)
	rootCmd.AddCommand(subscribeCmd)
	rootCmd.AddCommand(discoveryCmd)
	rootCmd.AddCommand(gencertCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	viper.SetEnvPrefix("OPCUA")
	viper.AutomaticEnv()
}
