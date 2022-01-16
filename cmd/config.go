// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/testifysec/witness/cmd/options"
)

func initConfig(rootCmd *cobra.Command, rootOptions *options.RootOptions) {
	v := viper.New()
	if _, err := os.Stat(rootOptions.Config); errors.Is(err, os.ErrNotExist) {
		if rootCmd.Flags().Lookup("config").Changed {
			log.Fatalf("config file %s does not exist", rootOptions.Config)
		} else {
			log.Printf("%s does not exist, using command line arguments", rootOptions.Config)
			return
		}
	}

	v.SetConfigFile(rootOptions.Config)

	if v.ConfigFileUsed() != "" {
		log.Println("Using config file:", v.ConfigFileUsed())
	}

	if err := v.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	//Currently we do not accept configuration for root commands
	commands := rootCmd.Commands()

	for _, cm := range commands {
		//Check which command we are running
		if !contains(os.Args, cm.Name()) {
			continue
		}
		flags := cm.Flags()
		flags.VisitAll(func(f *pflag.Flag) {
			configKey := fmt.Sprintf("%s.%s", cm.Name(), f.Name)

			if !f.Changed {
				if f.Value.Type() == "stringSlice" {
					configValue := v.GetStringSlice(configKey)
					if len(configValue) > 0 {
						for _, v := range configValue {
							if err := f.Value.Set(v); err != nil {
								log.Fatalf("Error setting config value: %s", err)
							}
						}
					}
				} else {
					configValue := v.GetString(configKey)
					if configValue != "" {
						if err := f.Value.Set(configValue); err != nil {
							log.Fatalf("Error setting config value: %s", err)
						}
					}
				}
			}
		})
	}

}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
