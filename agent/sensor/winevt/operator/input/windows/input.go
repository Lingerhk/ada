// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"ada/agent/sensor/winevt/operator"
	"ada/agent/sensor/winevt/operator/helper"
)

type eventFilters struct {
	EventID []uint32            `json:"EventID"` // [4624, 4625]
	Level   []uint8             `json:"Level"`   // [1,2,3]
	Custom  []map[string]string `json:"Custom"`  // {"field":"AccountName", "value":"SYSTEM", "op":"eq"}
}

// Input is an operator that creates entries using the windows event log api.
type Input struct {
	helper.InputOperator
	bookmark            Bookmark
	buffer              *Buffer
	channel             string
	maxReads            int
	currentMaxReads     int
	startAt             string
	raw                 bool
	eventFilter         string
	eventFilterList     *eventFilters
	excludeProviders    map[string]struct{}
	pollInterval        time.Duration
	persister           operator.Persister
	publisherCache      publisherCache
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	subscription        Subscription
	remote              RemoteConfig
	remoteSessionHandle windows.Handle
	startRemoteSession  func() error
	processEvent        func(context.Context, Event) error
}

// newInput creates a new Input operator.
func newInput(settings operator.TelemetrySettings) *Input {
	basicConfig := helper.NewBasicConfig("windowseventlog", "input")
	basicOperator, _ := basicConfig.Build(settings)

	input := &Input{
		InputOperator: helper.InputOperator{
			WriterOperator: helper.WriterOperator{
				BasicOperator: basicOperator,
			},
		},
	}
	input.startRemoteSession = input.defaultStartRemoteSession
	return input
}

// defaultStartRemoteSession starts a remote session for reading event logs from a remote server.
func (i *Input) defaultStartRemoteSession() error {
	if i.remote.Server == "" {
		return nil
	}

	login := EvtRPCLogin{
		Server:   windows.StringToUTF16Ptr(i.remote.Server),
		User:     windows.StringToUTF16Ptr(i.remote.Username),
		Password: windows.StringToUTF16Ptr(i.remote.Password),
	}

	sessionHandle, err := evtOpenSession(EvtRPCLoginClass, &login, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to open session for server %s: %w", i.remote.Server, err)
	}
	i.remoteSessionHandle = sessionHandle
	return nil
}

// stopRemoteSession stops the remote session if it is active.
func (i *Input) stopRemoteSession() error {
	if i.remoteSessionHandle != 0 {
		if err := evtClose(uintptr(i.remoteSessionHandle)); err != nil {
			return fmt.Errorf("failed to close remote session handle for server %s: %w", i.remote.Server, err)
		}
		i.remoteSessionHandle = 0
	}
	return nil
}

// isRemote checks if the input is configured for remote access.
func (i *Input) isRemote() bool {
	return i.remote.Server != ""
}

// isNonTransientError checks if the error is likely non-transient.
func isNonTransientError(err error) bool {
	return errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// Start will start reading events from a subscription.
func (i *Input) Start(persister operator.Persister) error {
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel

	i.persister = persister

	if i.isRemote() {
		if err := i.startRemoteSession(); err != nil {
			return fmt.Errorf("failed to start remote session for server %s: %w", i.remote.Server, err)
		}
	}

	// parse event filter
	if i.eventFilter != "" {
		// check event filter format: json {"ignores":[{"EventID":[1,2,3]}],"includes":[{"Level":[2,3]}]}
		var filters eventFilters
		err := json.Unmarshal([]byte(i.eventFilter), &filters)
		if err != nil {
			return fmt.Errorf("failed to parse event filter: %w", err)
		}
		i.eventFilterList = &filters
	}

	i.bookmark = NewBookmark()
	offsetXML, err := i.getBookmarkOffset(ctx)
	if err != nil {
		_ = i.persister.Delete(ctx, i.channel)
	}

	if offsetXML != "" {
		if err := i.bookmark.Open(offsetXML); err != nil {
			return fmt.Errorf("failed to open bookmark: %w", err)
		}
	}

	i.publisherCache = newPublisherCache()

	subscription := NewLocalSubscription()
	if i.isRemote() {
		subscription = NewRemoteSubscription(i.remote.Server)
	}

	if err := subscription.Open(i.startAt, uintptr(i.remoteSessionHandle), i.channel, i.bookmark); err != nil {
		if isNonTransientError(err) {
			if i.isRemote() {
				return fmt.Errorf("failed to open subscription for remote server %s: %w", i.remote.Server, err)
			}
			return fmt.Errorf("failed to open local subscription: %w", err)
		}
		if i.isRemote() {
			i.Logger().Warnf("Transient error opening subscription for remote server, continuing, server:%s, error:%v", i.remote.Server, err)
		} else {
			i.Logger().Warnf("Transient error opening local subscription, continuing, error:%v", err)
		}
	}

	i.subscription = subscription
	i.wg.Add(1)
	go i.readOnInterval(ctx)

	return nil
}

// Stop will stop reading events from a subscription.
func (i *Input) Stop() error {
	// Warning: all calls made below must be safe to be done even if Start() was not called or failed.

	if i.cancel != nil {
		i.cancel()
	}

	i.wg.Wait()

	var errs error
	if err := i.subscription.Close(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to close subscription: %w", err))
	}

	if err := i.bookmark.Close(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to close bookmark: %w", err))
	}

	if err := i.publisherCache.evictAll(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to close publishers: %w", err))
	}

	return errors.Join(errs, i.stopRemoteSession())
}

// readOnInterval will read events with respect to the polling interval until it reaches the end of the channel.
func (i *Input) readOnInterval(ctx context.Context) {
	defer i.wg.Done()

	ticker := time.NewTicker(i.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.read(ctx)
		}
	}
}

// read will read events from the subscription.
func (i *Input) read(ctx context.Context) {
	events, actualMaxReads, err := i.subscription.Read(i.currentMaxReads)

	// Update the current max reads if it changed
	if err == nil && actualMaxReads < i.currentMaxReads {
		i.currentMaxReads = actualMaxReads
		i.Logger().Debugf("Encountered RPC_S_INVALID_BOUND, reduced batch size, current_batch_size:%d, original_batch_size:%d", i.currentMaxReads, i.maxReads)
	}

	if err != nil {
		i.Logger().Errorf("Failed to read events from subscription, error:%v", err)
		if i.isRemote() && (errors.Is(err, windows.ERROR_INVALID_HANDLE) || errors.Is(err, errSubscriptionHandleNotOpen)) {
			i.Logger().Infof("Resubscribing, closing remote subscription")
			closeErr := i.subscription.Close()
			if closeErr != nil {
				i.Logger().Errorf("Failed to close remote subscription, error:%v", closeErr)
				return
			}
			if err := i.stopRemoteSession(); err != nil {
				i.Logger().Errorf("Failed to close remote session, error:%v", err)
			}
			i.Logger().Infof("Resubscribing, creating remote subscription")
			i.subscription = NewRemoteSubscription(i.remote.Server)
			if err := i.startRemoteSession(); err != nil {
				i.Logger().Errorf("Failed to re-establish remote session, error:%v", err)
				return
			}
			if err := i.subscription.Open(i.startAt, uintptr(i.remoteSessionHandle), i.channel, i.bookmark); err != nil {
				i.Logger().Errorf("Failed to re-open subscription for remote server, error:%v", err)
				return
			}
		}
		return
	}

	for n, event := range events {
		if err := i.processEvent(ctx, event); err != nil {
			i.Logger().Errorf("process event, error:%v", err)
		}
		if len(events) == n+1 {
			i.updateBookmarkOffset(ctx, event)
			if err := i.subscription.bookmark.Update(event); err != nil {
				i.Logger().Errorf("Failed to update bookmark from event, error:%v", err)
			}
		}
		event.Close()
	}
}

func (i *Input) getPublisherName(event Event) (name string, excluded bool) {
	providerName, err := event.GetPublisherName(i.buffer)
	if err != nil {
		i.Logger().Errorf("Failed to get provider name, error:%v", err)
		return "", true
	}
	if _, exclude := i.excludeProviders[providerName]; exclude {
		return "", true
	}

	return providerName, false
}

func (i *Input) renderSimpleAndSend(ctx context.Context, event Event) error {
	simpleEvent, err := event.RenderSimple(i.buffer)
	if err != nil {
		return fmt.Errorf("render simple event: %w", err)
	}
	return i.sendEvent(ctx, simpleEvent)
}

func (i *Input) renderDeepAndSend(ctx context.Context, event Event, publisher Publisher) error {
	deepEvent, err := event.RenderDeep(i.buffer, publisher)
	if err == nil {
		return i.sendEvent(ctx, deepEvent)
	}
	return errors.Join(
		fmt.Errorf("render deep event: %w", err),
		i.renderSimpleAndSend(ctx, event),
	)
}

// processEvent will process and send an event retrieved from windows event log.
func (i *Input) processEventWithoutRenderingInfo(ctx context.Context, event Event) error {
	if len(i.excludeProviders) == 0 {
		return i.renderSimpleAndSend(ctx, event)
	}
	if _, exclude := i.getPublisherName(event); exclude {
		return nil
	}
	return i.renderSimpleAndSend(ctx, event)
}

func (i *Input) processEventWithRenderingInfo(ctx context.Context, event Event) error {
	providerName, exclude := i.getPublisherName(event)
	if exclude {
		return nil
	}

	publisher, err := i.publisherCache.get(providerName)
	if err != nil {
		return errors.Join(
			fmt.Errorf("open event source for provider %q: %w", providerName, err),
			i.renderSimpleAndSend(ctx, event),
		)
	}

	if publisher.Valid() {
		return i.renderDeepAndSend(ctx, event, publisher)
	}
	return i.renderSimpleAndSend(ctx, event)
}

// sendEvent will send EventXML as an entry to the operator's output.
func (i *Input) sendEvent(ctx context.Context, eventXML *EventXML) error {
	var body any = eventXML.Original
	if !i.raw {
		body = formattedBody(eventXML)
	}

	if !i.executeEventFilter(eventXML) {
		return nil
	}

	e, err := i.NewEntry(body)
	if err != nil {
		return fmt.Errorf("create entry: %w", err)
	}

	e.Timestamp = parseTimestamp(eventXML.TimeCreated.SystemTime)

	if i.remote.Server != "" {
		e.Attributes["server.address"] = i.remote.Server
	}

	return i.Write(ctx, e)
}

// getBookmarkXML will get the bookmark xml from the offsets database.
func (i *Input) getBookmarkOffset(ctx context.Context) (string, error) {
	bytes, err := i.persister.Get(ctx, i.channel)
	return string(bytes), err
}

// updateBookmark will update the bookmark xml and save it in the offsets database.
func (i *Input) updateBookmarkOffset(ctx context.Context, event Event) {
	if err := i.bookmark.Update(event); err != nil {
		i.Logger().Errorf("Failed to update bookmark from event, error:%v", err)
		return
	}

	bookmarkXML, err := i.bookmark.Render(i.buffer)
	if err != nil {
		i.Logger().Errorf("Failed to render bookmark xml, error:%v", err)
		return
	}

	if err := i.persister.Set(ctx, i.channel, []byte(bookmarkXML)); err != nil {
		i.Logger().Errorf("failed to set offsets, error:%v", err)
		return
	}
}

// executeEventFilter will execute the event filter and return true if the event should be processed.
func (i *Input) executeEventFilter(eventXML *EventXML) bool {
	if i.eventFilterList == nil {
		return true
	}

	// Check ignores
	if len(i.eventFilterList.EventID) > 0 {
		for _, eventid := range i.eventFilterList.EventID {
			if eventid == eventXML.EventID.ID {
				return false
			}
		}
	}
	if len(i.eventFilterList.Level) > 0 {
		for _, level := range i.eventFilterList.Level {
			if level == eventXML.Level {
				return false
			}
		}
	}

	// Check custom filters
	if len(i.eventFilterList.Custom) > 0 {
		for _, custom := range i.eventFilterList.Custom {
			field := custom["field"] // EventID, Level, etc.
			value := custom["value"]
			op := custom["op"] // eq, ne, startswith, endswith, contains

			structValue := reflect.ValueOf(eventXML)
			fieldValue := structValue.FieldByName(field)
			if !fieldValue.IsValid() {
				continue
			}

			switch op {
			case "eq":
				if fieldValue.String() == value {
					return false
				}
			case "ne":
				if fieldValue.String() != value {
					return false
				}
			case "startswith":
				if strings.HasPrefix(fieldValue.String(), value) {
					return false
				}
			case "endswith":
				if strings.HasSuffix(fieldValue.String(), value) {
					return false
				}
			case "contains":
				if strings.Contains(fieldValue.String(), value) {
					return false
				}
			}
		}
	}

	return true
}
