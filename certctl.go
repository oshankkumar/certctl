package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCertCtl() *cobra.Command {
	opts := &CertCtlRunOptions{}
	cmd := &cobra.Command{
		Use:   "certctl",
		Short: "command line tool to generate ssl certificates and key",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			opts.Init()
		},
	}
	// add flags
	cmd.PersistentFlags().BoolVarP(&opts.Debug, "debug", "d", false, "enable debug mode")
	//add sub-commands
	cmd.AddCommand(NewCreateCmd())
	return cmd
}

type CertCtlRunOptions struct {
	Debug bool
}

func (opts *CertCtlRunOptions) Init() {
	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}
}
