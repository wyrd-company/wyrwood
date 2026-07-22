//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

// Handler is the daemon-owned operation boundary used by the local server.
type Handler interface {
	Apply() (ApplyResult, ErrorCode)
	Keys() (KeysResult, ErrorCode)
	Status() (StatusResult, ErrorCode)
	Events(limit int) (EventsResult, ErrorCode)
	Configuration(offset, limit int, expectedRevision *string) (ConfigurationResult, ErrorCode)
	SetUpstream(expectedRevision, upstream string) (ConfigurationChangeResult, ErrorCode)
	SetTimeouts(expectedRevision string, timeouts ConfigurationTimeouts) (ConfigurationChangeResult, ErrorCode)
	PutConsumer(expectedRevision string, consumerID *string, consumer ConfigurationConsumerInput) (ConfigurationChangeResult, ErrorCode)
	RetireConsumer(expectedRevision, consumerID string) (ConfigurationChangeResult, ErrorCode)
}

func dispatch(handler Handler, request Request) Response {
	response := Response{Version: Version, Error: ErrorNone}
	if code := validateRequest(request); code != ErrorNone {
		response.Error = code
		return response
	}
	switch request.Operation {
	case OperationApply:
		result, code := handler.Apply()
		response.Error = code
		if code == ErrorNone {
			response.OK, response.Apply = true, &result
		}
	case OperationKeys:
		result, code := handler.Keys()
		response.Error = code
		if code == ErrorNone {
			response.OK, response.Keys = true, &result
		}
	case OperationStatus:
		result, code := handler.Status()
		response.Error = code
		if code == ErrorNone {
			response.OK, response.Status = true, &result
		}
	case OperationEvents:
		result, code := handler.Events(*request.Limit)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.Events = true, &result
		}
	case OperationConfiguration:
		result, code := handler.Configuration(*request.Offset, *request.Limit, request.ExpectedRevision)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.Configuration = true, &result
		}
	case OperationSetUpstream:
		result, code := handler.SetUpstream(*request.ExpectedRevision, *request.Upstream)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.ConfigurationChange = true, &result
		}
	case OperationSetTimeouts:
		result, code := handler.SetTimeouts(*request.ExpectedRevision, *request.Timeouts)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.ConfigurationChange = true, &result
		}
	case OperationPutConsumer:
		result, code := handler.PutConsumer(*request.ExpectedRevision, request.ConsumerID, *request.Consumer)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.ConfigurationChange = true, &result
		}
	case OperationRetireConsumer:
		result, code := handler.RetireConsumer(*request.ExpectedRevision, *request.ConsumerID)
		response.Error = code
		if code == ErrorNone {
			response.OK, response.ConfigurationChange = true, &result
		}
	}
	return response
}
