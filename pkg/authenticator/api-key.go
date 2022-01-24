package authenticator

import (
	"github.com/GunaKKIBM/secret-utils-lib/pkg/token"
	"github.com/GunaKKIBM/secret-utils-lib/pkg/utils"
	"github.com/IBM/go-sdk-core/v5/core"
	"go.uber.org/zap"
)

// APIKeyAuthenticator ...
type APIKeyAuthenticator struct {
	authenticator *core.IamAuthenticator
	logger        *zap.Logger
}

// NewIamAuthenticator ...
func NewIamAuthenticator(apikey string, logger *zap.Logger) *APIKeyAuthenticator {
	logger.Info("Initializing iam authenticator")
	defer logger.Info("Initialized iam authenticator")
	ca := new(APIKeyAuthenticator)
	ca.authenticator = new(core.IamAuthenticator)
	ca.authenticator.ApiKey = apikey
	ca.logger = logger
	return ca
}

// GetToken ...
func (aa *APIKeyAuthenticator) GetToken(freshTokenRequired bool) (string, uint64, error) {
	aa.logger.Info("Fetching IAM token using api key authenticator")
	var iamtoken string
	var err error
	var tokenlifetime uint64

	if !freshTokenRequired {
		aa.logger.Info("Retreiving existing token")
		iamtoken, err = aa.authenticator.GetToken()
		if err != nil {
			aa.logger.Error("Error fetching token", zap.Error(err))
			return "", tokenlifetime, err
		}
		tokenlifetime, err = token.FetchTokenLifeTime(iamtoken)
		if err != nil {
			aa.logger.Error("Error fetching tokenlifetime", zap.Error(err))
			return "", tokenlifetime, err
		}
		if tokenlifetime > utils.TokenExpirydiff {
			aa.logger.Info("Successfully fetched IAM token")
			return iamtoken, tokenlifetime, nil
		}
	}

	tokenResponse, err := aa.authenticator.RequestToken()
	if err != nil {
		aa.logger.Error("Error fetching fresh token", zap.Error(err))
		return "", tokenlifetime, err
	}

	tokenlifetime, err = token.FetchTokenLifeTime(tokenResponse.AccessToken)
	if err != nil {
		aa.logger.Error("Error fetching tokenlifetime", zap.Error(err))
		return "", tokenlifetime, err
	}
	aa.logger.Info("Successfully fetched IAM token")
	return tokenResponse.AccessToken, tokenlifetime, nil
}
