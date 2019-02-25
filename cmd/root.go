package cmd

import (
    "fmt"
    "io/ioutil"
    "os"

    "github.com/buger/jsonparser"

    "github.com/spf13/cobra"

    "github.com/newscorp-ghfb/okta-kubectl-auth/pkg/okta"
)

type Flags struct {
	Debug        bool
    ClientID     string
    ClientSecret string
	BaseDomain   string
	BindAddr     string
	InputConfig  string
    Username     string
    KubeConfig   string
}

var flags = &Flags{}

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use: "okta-kubectl-auth authorize",
	Short: "Okta login helper for kubectl",
	Example: `
  To run with a config file:
  okta-kubectl-auth authorize --config=/path/to/config/file.json

  To run without a config file:
  okta-kubectl-auth authorize --client-id=<id> --client-secret=<secret> --base-domain=<domain>

  To automatically configure your kubeconfig supply the username and kubeconfig flags:
  okta-kubectl-auth authorize --config=/path/to/config/file.json --username=<name> --kubeconfig=/path/to/kubeconfig`,
  	PreRunE: func(cmd *cobra.Command, args []string) error {
	    if flags.ClientID == "" && flags.InputConfig == "" {
	      cmd.Help()
	      os.Exit(1)
	    }
	    return nil
  	},
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
    o.BindAddr = flags.BindAddr
	o.Debug = flags.Debug
	o.KubeConfig = flags.KubeConfig
	o.Username = flags.Username

    if flags.InputConfig != "" {
    	o.ClientID, o.ClientSecret, o.BaseDomain = ParseConfig(flags.InputConfig, flags.Username)
    } else {
    	o.ClientID = flags.ClientID
        o.ClientSecret = flags.ClientSecret
        o.BaseDomain = flags.BaseDomain
	}

	return o
}

func ParseConfig(path string, username string) (string, string, string) {
	jsonConfig, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
	}

	id, _, _, _ := jsonparser.Get(jsonConfig, username, "id")
	secret, _, _, _ := jsonparser.Get(jsonConfig, username, "secret")
	uri, _, _, _ := jsonparser.Get(jsonConfig, username, "uri")

	return string(id), string(secret), string(uri)
}

func init() {
	RootCmd.Flags().StringVar(&flags.ClientID, "client-id", "", "OAuth2 client ID of this application.")
	RootCmd.Flags().StringVar(&flags.ClientSecret, "client-secret", "", "OAuth2 client secret of this application.")

	RootCmd.PersistentFlags().StringVar(&flags.BaseDomain, "base-domain", "", "URL of the OpenID Connect issuer.")
	RootCmd.PersistentFlags().StringVar(&flags.BindAddr, "bind-addr", "127.0.0.1:8888", "HTTP address to listen at.")
	RootCmd.PersistentFlags().BoolVar(&flags.Debug, "debug", false, "Raise log level to debug.")

	RootCmd.PersistentFlags().StringVar(&flags.KubeConfig, "kubeconfig", "", "Path to the kubeconfig you want to update.")
	RootCmd.PersistentFlags().StringVar(&flags.InputConfig, "config", "", "Path to a json file containing the required keys/tokens. (see README)")
	RootCmd.PersistentFlags().StringVar(&flags.Username, "username", "", "Username/cluster to use when setting credentials in the kubeconfig.")
}
