package handlers

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/authelia/authelia/internal/authentication"
	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/regulation"
	"github.com/authelia/authelia/internal/session"
)

const movingAverageWindow = 10

var execDurationMovingAverage = make([]time.Duration, movingAverageWindow)
var movingAverageCursor = 0

func init() {
	for i := range execDurationMovingAverage {
		execDurationMovingAverage[i] = 1 * time.Second
	}
}

func delayToPreventTimingAttacks(startTime time.Time) {
	execDuration := time.Now().Sub(startTime)
	// Take the moving average of execution time to smooth the differences between existing users and non existing (maybe it's not even necessary)
	// It could be noticeable if the difference of execution time between user existing and non existing.
	avgExecDuration := movingAverageIteration(execDuration)
	minDelay := int64(250 * time.Millisecond)
	// Let say the avg execution time is Et, we generate a delay D which satisfies 250ms <= D <= Et. There is minimum value so that
	// even if the handler fails promptly on an error, it would not even be noticeable for an attacker.
	randomDelayMs := minDelay + rand.Int63n(int64(math.Max(0.0, avgExecDuration-float64(minDelay))))
	time.Sleep(time.Duration(randomDelayMs) * time.Millisecond)
}

func movingAverageIteration(value time.Duration) float64 {
	currentPos := movingAverageCursor
	execDurationMovingAverage[currentPos] = value
	movingAverageCursor = (movingAverageCursor + 1) % movingAverageWindow

	sum := 0.0
	for _, v := range execDurationMovingAverage {
		sum += float64(v)
	}
	return sum / 10.0
}

// FirstFactorPost generates the handler performing the first factor authentication factory.
//nolint:gocyclo // TODO: Consider refactoring time permitting.
func FirstFactorPost(ctx *middlewares.AutheliaCtx) {
	receivedTime := time.Now()
	defer delayToPreventTimingAttacks(receivedTime)

	bodyJSON := firstFactorRequestBody{}
	err := ctx.ParseBody(&bodyJSON)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, err, authenticationFailedMessage)
		return
	}

	bannedUntil, err := ctx.Providers.Regulator.Regulate(bodyJSON.Username)

	if err != nil {
		if err == regulation.ErrUserIsBanned {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("User %s is banned until %s", bodyJSON.Username, bannedUntil), authenticationFailedMessage)
			return
		}

		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regulate authentication: %s", err), authenticationFailedMessage)

		return
	}

	userPasswordOk, err := ctx.Providers.UserProvider.CheckUserPassword(bodyJSON.Username, bodyJSON.Password)

	if err != nil {
		ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)
		ctx.Providers.Regulator.Mark(bodyJSON.Username, false) //nolint:errcheck // TODO: Legacy code, consider refactoring time permitting.
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Error while checking password for user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
		return
	}

	if !userPasswordOk {
		ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)
		ctx.Providers.Regulator.Mark(bodyJSON.Username, false) //nolint:errcheck // TODO: Legacy code, consider refactoring time permitting.
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Credentials are wrong for user %s", bodyJSON.Username), authenticationFailedMessage)
		return
	}

	ctx.Logger.Debugf("Credentials validation of user %s is ok", bodyJSON.Username)

	ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)
	err = ctx.Providers.Regulator.Mark(bodyJSON.Username, true)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to mark authentication: %s", err), authenticationFailedMessage)
		return
	}

	// Reset all values from previous session before regenerating the cookie.
	err = ctx.SaveSession(session.NewDefaultUserSession())

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to reset the session for user %s: %s", bodyJSON.Username, err), authenticationFailedMessage)
		return
	}

	err = ctx.Providers.SessionProvider.RegenerateSession(ctx.RequestCtx)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regenerate session for user %s: %s", bodyJSON.Username, err), authenticationFailedMessage)
		return
	}

	// Check if bodyJSON.KeepMeLoggedIn can be deref'd and derive the value based on the configuration and JSON data
	keepMeLoggedIn := ctx.Providers.SessionProvider.RememberMe != 0 && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

	// Set the cookie to expire if remember me is enabled and the user has asked us to
	if keepMeLoggedIn {
		err = ctx.Providers.SessionProvider.UpdateExpiration(ctx.RequestCtx, ctx.Providers.SessionProvider.RememberMe)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update expiration timer for user %s: %s", bodyJSON.Username, err), authenticationFailedMessage)
			return
		}
	}

	// Get the details of the given user from the user provider.
	userDetails, err := ctx.Providers.UserProvider.GetDetails(bodyJSON.Username)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Error while retrieving details from user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
		return
	}

	ctx.Logger.Tracef("Details for user %s => groups: %s, emails %s", bodyJSON.Username, userDetails.Groups, userDetails.Emails)

	// And set those information in the new session.
	userSession := ctx.GetSession()
	userSession.Username = userDetails.Username
	userSession.Groups = userDetails.Groups
	userSession.Emails = userDetails.Emails
	userSession.AuthenticationLevel = authentication.OneFactor
	userSession.LastActivity = time.Now().Unix()
	userSession.KeepMeLoggedIn = keepMeLoggedIn
	refresh, refreshInterval := getProfileRefreshSettings(ctx.Configuration.AuthenticationBackend)

	if refresh {
		userSession.RefreshTTL = ctx.Clock.Now().Add(refreshInterval)
	}

	err = ctx.SaveSession(userSession)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to save session of user %s", bodyJSON.Username), authenticationFailedMessage)
		return
	}

	Handle1FAResponse(ctx, bodyJSON.TargetURL, userSession.Username, userSession.Groups)
}
