package flag

import (
	"time"

	"golang.org/x/xerrors"

	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
)

var (
	cloudUpdateCacheFlag = trivyflag.Flag[bool]{
		Name:       "update-cache",
		ConfigName: "cloud.update-cache",
		Usage:      "Update the cache for the applicable cloud provider instead of using cached results.",
	}
	cloudMaxCacheAgeFlag = trivyflag.Flag[time.Duration]{
		Name:       "max-cache-age",
		ConfigName: "cloud.max-cache-age",
		Default:    time.Hour * 24,
		Usage:      "The maximum age of the cloud cache. Cached data will be required from the cloud provider if it is older than this.",
	}
)

type CloudFlagGroup struct {
	UpdateCache *trivyflag.Flag[bool]
	MaxCacheAge *trivyflag.Flag[time.Duration]
}

type CloudOptions struct {
	MaxCacheAge time.Duration
	UpdateCache bool
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		UpdateCache: cloudUpdateCacheFlag.Clone(),
		MaxCacheAge: cloudMaxCacheAgeFlag.Clone(),
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Cloud"
}

func (f *CloudFlagGroup) Flags() []trivyflag.Flagger {
	return []trivyflag.Flagger{
		f.UpdateCache,
		f.MaxCacheAge,
	}
}

func (f *CloudFlagGroup) ToOptions(opts *trivyflag.Options) error {
	return nil
}

func (f *CloudFlagGroup) ToPluginOptions(opts *Options) error {
	opts.CloudOptions = CloudOptions{
		UpdateCache: f.UpdateCache.Value(),
		MaxCacheAge: f.MaxCacheAge.Value(),
	}
	return nil
}

func parseFlags(fg trivyflag.FlagGroup) error {
	for _, flag := range fg.Flags() {
		if err := flag.Parse(); err != nil {
			return xerrors.Errorf("unable to parse flag: %w", err)
		}
	}
	return nil
}
