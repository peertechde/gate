package controlapi

import (
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"peertech.de/gate/internal/session"
)

func toSessionModel(s session.Session) Session {
	var endTime *time.Time
	if !s.EndTime.IsZero() {
		endTime = &s.EndTime
	}

	parsedID, err := uuid.Parse(s.ID)
	if err != nil {
		parsedID = uuid.Nil
	}

	state := Active
	if s.State == session.StateTerminated {
		state = Terminated
	}

	var terminationReason *TerminationReason
	if s.TerminationReason != "" {
		reason := mapTerminationReason(s.TerminationReason)
		terminationReason = &reason
	}

	return Session{
		SessionId:            openapi_types.UUID(parsedID),
		UserName:             s.UserName,
		PublicKeyFingerprint: s.PublicKeyFingerprint,
		SourceIp:             s.SourceIP,
		StartTime:            s.StartTime,
		EndTime:              endTime,
		State:                state,
		TerminationReason:    terminationReason,
	}
}

func mapTerminationReason(reason session.TerminationReason) TerminationReason {
	switch reason {
	case session.TerminationReasonRevoked:
		return Revoked
	case session.TerminationReasonAdminTerminated:
		return AdminTerminated
	case session.TerminationReasonMaxDuration:
		return MaxDuration
	case session.TerminationReasonError:
		return Error
	default:
		return Error
	}
}
