package main

import (
	"fmt"
	"io/ioutil"
	"os"

	notaryclient "github.com/docker/notary/client"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cmdDelegationTemplate = usageTemplate{
	Use:   "delegation",
	Short: "Operates on delegations.",
	Long:  `Operations on TUF delegations.`,
}

var cmdDelegationListTemplate = usageTemplate{
	Use:   "list [ GUN ]",
	Short: "Lists delegations for the Global Unique Name.",
	Long:  "Lists all delegations known to notary for a specific Global Unique Name.",
}

var cmdDelegationRemoveTemplate = usageTemplate{
	Use:   "remove [ GUN ] [ KeyID ] [ Role ]",
	Short: "Remove a Role delegation for the KeyID.",
	Long:  "Remove a Role delegation for the KeyID in a specific Global Unique Name.",
}

var cmdDelegationAddTemplate = usageTemplate{
	Use:   "add [ GUN ] [ Path to PEM file ] [ Role ] <delegation path 1> ...",
	Short: "Add a Role delegation for the provided public key certificate PEM.",
	Long:  "Add a Role delegation for the provided public key certificate PEM in a specific Global Unique Name.",
}

type delegationCommander struct {
	// these need to be set
	configGetter func() *viper.Viper
	retriever    passphrase.Retriever
}

func (d *delegationCommander) GetCommand() *cobra.Command {
	cmd := cmdDelegationTemplate.ToCommand(nil)
	cmd.AddCommand(cmdDelegationListTemplate.ToCommand(d.delegationsList))
	cmd.AddCommand(cmdDelegationRemoveTemplate.ToCommand(d.delegationRemove))
	cmd.AddCommand(cmdDelegationAddTemplate.ToCommand(d.delegationAdd))

	return cmd
}

// delegationsList lists all the delegations for a particular GUN
func (d *delegationCommander) delegationsList(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf(
			"Please provide a Global Unique Name as an argument to list")
	}

	config := d.configGetter()

	gun := args[0]

	// initialize repo with transport to get latest state of the world before listing delegations
	nRepo, err := notaryclient.NewNotaryRepository(config.GetString("trust_dir"), gun, getRemoteTrustServer(config), getTransport(config, gun, true), retriever)
	if err != nil {
		fatalf(err.Error())
	}

	delegationRoles, err := nRepo.GetDelegationRoles()
	if err != nil {
		return fmt.Errorf("Error retrieving delegation roles for repository %s: %v", gun, err)
	}

	cmd.Println("")
	prettyPrintRoles(delegationRoles, cmd.Out())
	cmd.Println("")
	return nil
}

// delegationRemove removes a public key from a specific role in a GUN
func (d *delegationCommander) delegationRemove(cmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("must specify the Global Unique Name, the Key ID and the role of the delegation to remove")
	}

	config := d.configGetter()

	gun := args[0]
	keyID := args[1]
	role := args[2]

	// no online operations are performed by add so the transport argument
	// should be nil
	nRepo, err := notaryclient.NewNotaryRepository(config.GetString("trust_dir"), gun, getRemoteTrustServer(config), nil, retriever)
	if err != nil {
		fatalf(err.Error())
	}

	// Add the delegation to the repository
	err = nRepo.RemoveDelegation(role)
	if err != nil {
		return fmt.Errorf("failed to remove delegation: %v", err)
	}
	cmd.Println("")
	cmd.Printf(
		"Removal of delegation of key \"%s\" to role %s, to repository \"%s\" staged for next publish.\n",
		keyID, role, gun)
	cmd.Println("")

	return nil
}

// delegationAdd adds a public key from a certificate to a specific role in a GUN
func (d *delegationCommander) delegationAdd(cmd *cobra.Command, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("must specify the Global Unique Name, the public key certificate path, the role of the delegation to add and a list of paths")
	}

	config := d.configGetter()

	gun := args[0]
	pubKeyPath := args[1]
	role := args[2]
	paths := args[3:]

	// Check to see if the public key file exists
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("pub key file does not exist: %s", pubKeyPath)
	}

	// Read public key bytes from PEM file
	pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("unable to read public key from file: %s", pubKeyPath)
	}

	// Parse PEM bytes into type PublicKey
	pubKey, err := trustmanager.ParsePEMPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to parse valid public key certificate from PEM file %s: %v", pubKeyPath, err)
	}

	keyID := pubKey.ID()

	// Check to see if it is an invalid ID
	if len(keyID) != idSize {
		return fmt.Errorf("invalid key ID provided: %s", keyID)
	}

	// no online operations are performed by add so the transport argument
	// should be nil
	nRepo, err := notaryclient.NewNotaryRepository(config.GetString("trust_dir"), gun, getRemoteTrustServer(config), nil, retriever)
	if err != nil {
		fatalf(err.Error())
	}

	// Add the delegation to the repository
	err = nRepo.AddDelegation(role, 1, []data.PublicKey{pubKey}, paths)
	if err != nil {
		return fmt.Errorf("failed to add delegation: %v", err)
	}

	cmd.Println("")
	cmd.Printf(
		"Addition of delegation of key \"%s\" to role %s with paths %s, to repository \"%s\" staged for next publish.\n",
		keyID, role, paths, gun)
	cmd.Println("")
	return nil
}
