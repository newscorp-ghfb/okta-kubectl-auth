package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/newscorp-ghfb/okta-kubectl-auth/pkg/okta"
)

type Flags struct {
	Debug        bool
	ClientID     string
	ClientSecret string
	BaseDomain   string
	BindAddr     string
    Username     string
    KubeConfig   string
}

var flags = &Flags{}

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "okta-kubectl-auth",
	Short: "Okta login helper for kubectl",
	RunE: func(cmd *cobra.Command, args []string) error {
		o := newOkta(flags)

		if err := o.Authorize(nil); err != nil {
			return fmt.Errorf("failed to authorise: %s", err)
		}

		return nil

	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func newOkta(flags *Flags) *okta.Okta {
	o := okta.New(nil, flags.Debug)
	o.BaseDomain = flags.BaseDomain
	o.BindAddr = flags.BindAddr
	o.ClientID = flags.ClientID
	o.ClientSecret = flags.ClientSecret
	o.Debug = flags.Debug
	o.KubeConfig = flags.KubeConfig
	o.Username = flags.Username
	return o
}

func init() {
	RootCmd.Flags().StringVar(&flags.ClientID, "client-id", "", "OAuth2 client ID of this application. (required)")
	RootCmd.MarkFlagRequired("client-id")
	RootCmd.Flags().StringVar(&flags.ClientSecret, "client-secret", "", "OAuth2 client secret of this application. (required)")
	RootCmd.MarkFlagRequired("client-secret")

	RootCmd.PersistentFlags().StringVar(&flags.BaseDomain, "base-domain", "", "URL of the OpenID Connect issuer. (required)")
	RootCmd.MarkPersistentFlagRequired("base-domain")
	RootCmd.PersistentFlags().StringVar(&flags.BindAddr, "bind-addr", "127.0.0.1:8888", "HTTP address to listen at.")
	RootCmd.PersistentFlags().BoolVar(&flags.Debug, "debug", false, "Raise log level to debug.")

	RootCmd.PersistentFlags().StringVar(&flags.KubeConfig, "kubeconfig", "<kubeconfig_path>", "Path to the kubeconfig you want to update.")
	RootCmd.PersistentFlags().StringVar(&flags.Username, "username", "<username>", "Username to use when setting credentials in the kubeconfig.")

}
