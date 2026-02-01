package main

import (
	"fmt"

	"github.com/edgeo/drivers/opcua"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		info := opcua.GetVersion()
		fmt.Printf("opcuacli version %s\n", info.Version)
	},
}
