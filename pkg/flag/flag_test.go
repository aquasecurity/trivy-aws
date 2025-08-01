package flag_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-aws/pkg/flag"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
)

func TestFlag_ToOptions(t *testing.T) {
	t.Cleanup(viper.Reset)

	group := flag.NewCloudFlagGroup()
	flags := flag.Flags{
		BaseFlags: trivyflag.Flags{
			trivyflag.NewGlobalFlagGroup(),
		},
		CloudFlagGroup: group,
	}

	viper.Set(trivyflag.DebugFlag.ConfigName, true)
	viper.Set(trivyflag.ConfigFileFlag.ConfigName, "test.yaml")
	viper.Set(trivyflag.CacheDirFlag.ConfigName, "./cache")

	viper.Set(group.MaxCacheAge.ConfigName, "48h")
	viper.Set(group.UpdateCache.ConfigName, true)

	got, err := flags.ToOptions(nil)
	require.NoError(t, err)

	expected := flag.Options{
		Options: trivyflag.Options{
			GlobalOptions: trivyflag.GlobalOptions{
				Debug:      true,
				ConfigFile: "test.yaml",
				CacheDir:   "./cache",
			},
			AppVersion: "dev",
		},
		CloudOptions: flag.CloudOptions{
			MaxCacheAge: time.Duration(48) * time.Hour,
			UpdateCache: true,
		},
	}

	assert.Equal(t, expected.AppVersion, got.AppVersion)
	assert.Equal(t, expected.GlobalOptions, got.GlobalOptions)
	assert.Equal(t, expected.CloudOptions, got.CloudOptions)
}

func TestCloudFlagGroup_ToOptions(t *testing.T) {
	t.Cleanup(viper.Reset)

	group := flag.NewCloudFlagGroup()
	viper.Set(group.MaxCacheAge.ConfigName, "48h")
	viper.Set(group.UpdateCache.ConfigName, true)

	flags := flag.Flags{
		CloudFlagGroup: group,
	}
	got, err := flags.ToOptions(nil)
	require.NoError(t, err)

	expected := flag.CloudOptions{
		MaxCacheAge: time.Duration(48) * time.Hour,
		UpdateCache: true,
	}

	assert.Equal(t, expected, got.CloudOptions)
}
