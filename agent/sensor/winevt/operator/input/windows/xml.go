// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package windows

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

// Keyword Constants
const (
	keywordAuditFailure = 0x10000000000000
	keywordAuditSuccess = 0x20000000000000
)

// define the static values that are a common across Windows. These
// values are from winmeta.xml inside the Windows SDK.
var winMetaKeywords = map[uint64]string{
	0:                  "AnyKeyword",
	0x1000000000000:    "ResponseTime",
	0x2000000000000:    "WDIContext",
	0x4000000000000:    "WDIDiag",
	0x8000000000000:    "SQM",
	0x10000000000000:   "AuditFailure",
	0x20000000000000:   "AuditSuccess",
	0x40000000000000:   "CorrelationHint",
	0x80000000000000:   "EventlogClassic",
	0x100000000000000:  "ReservedKeyword56",
	0x200000000000000:  "ReservedKeyword57",
	0x400000000000000:  "ReservedKeyword58",
	0x800000000000000:  "ReservedKeyword59",
	0x1000000000000000: "ReservedKeyword60",
	0x2000000000000000: "ReservedKeyword61",
	0x4000000000000000: "ReservedKeyword62",
	0x8000000000000000: "ReservedKeyword63",
}

var winMetaOpcodes = map[uint8]string{
	0: "Info",
	1: "Start",
	2: "Stop",
	3: "DCStart",
	4: "DCStop",
	5: "Extension",
	6: "Reply",
	7: "Resume",
	8: "Suspend",
	9: "Send",
}

var winMetaLevels = map[uint8]string{
	0: "Information", // "Log Always", but Event Viewer shows Information.
	1: "Critical",
	2: "Error",
	3: "Warning",
	4: "Information",
	5: "Verbose",
}

// SIDType identifies the type of a security identifier (SID).
type SIDType uint32

const (
	// Do not reorder.
	SidTypeUser SIDType = 1 + iota
	SidTypeGroup
	SidTypeDomain
	SidTypeAlias
	SidTypeWellKnownGroup
	SidTypeDeletedAccount
	SidTypeInvalid
	SidTypeUnknown
	SidTypeComputer
	SidTypeLabel
	SidTypeLogonSession
)

// sidTypeToString is a mapping of SID types to their string representations.
var sidTypeToString = map[SIDType]string{
	SidTypeUser:           "User",
	SidTypeGroup:          "Group",
	SidTypeDomain:         "Domain",
	SidTypeAlias:          "Alias",
	SidTypeWellKnownGroup: "Well Known Group",
	SidTypeDeletedAccount: "Deleted Account",
	SidTypeInvalid:        "Invalid",
	SidTypeUnknown:        "Unknown",
	SidTypeComputer:       "Computer",
	SidTypeLabel:          "Label",
	SidTypeLogonSession:   "Logon Session",
}

// EventXML is the rendered xml of an event.
type EventXML struct {
	Original         string       `xml:"-"`
	EventID          EventID      `xml:"System>EventID"`
	Provider         Provider     `xml:"System>Provider"`
	Computer         string       `xml:"System>Computer"`
	Channel          string       `xml:"System>Channel"`
	RecordID         uint64       `xml:"System>EventRecordID"`
	TimeCreated      TimeCreated  `xml:"System>TimeCreated"`
	Version          uint8        `xml:"System>Version"`
	Message          string       `xml:"RenderingInfo>Message"`
	Level            uint8        `xml:"System>Level"`                   //
	Task             uint16       `xml:"System>Task"`                    //
	Opcode           *uint8       `xml:"System>Opcode"`                  //
	Keywords         []string     `xml:"System>Keywords"`                //
	RenderedLevel    string       `xml:"RenderingInfo>Level"`            // rendered to local language
	RenderedTask     string       `xml:"RenderingInfo>Task"`             // rendered to local language
	RenderedOpcode   string       `xml:"RenderingInfo>Opcode"`           // rendered to local language
	RenderedKeywords []string     `xml:"RenderingInfo>Keywords>Keyword"` // rendered to local language
	Security         *Security    `xml:"System>Security"`
	Execution        *Execution   `xml:"System>Execution"`
	Correlation      *Correlation `xml:"System>Correlation"`
	EventData        EventData    `xml:"EventData"`
}

// parseTimestamp will parse the timestamp of the event.
func parseTimestamp(ts string) int64 {
	if timestamp, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return timestamp.UnixMilli()
	}
	return time.Now().UnixMilli()
}

// parseWinMeta translates raw numeric system values (Level, Task, Opcode, Keywords)
// into human-readable strings using defaultWinMeta if the rendered versions are not available.
// It prioritizes rendered values and follows logic similar to Elastic Beats' EnrichRawValuesWithNames.
func parseWinMeta(e *EventXML) (string, string, string, []string) {
	// Level
	// finalLevel := e.RenderedLevel
	// if finalLevel == "" {
	// 	finalLevel = winMetaLevels[e.Level]
	// }
	finalLevel, ok := winMetaLevels[e.Level] // we don't using rendered level(it is local language)
	if !ok {
		finalLevel = e.RenderedLevel
	}

	// Opcode
	opcode := e.RenderedOpcode
	if opcode == "" {
		if e.Opcode != nil {
			opcode, _ = winMetaOpcodes[*e.Opcode]
		} else {
			zeroOpcode := uint8(0)
			e.Opcode = &zeroOpcode
		}
	}

	// Keywords
	keywords := e.RenderedKeywords
	if keywords == nil {
		keywords = e.Keywords
	}

	var outcome string
	finalKeywords := []string{}
	for _, keyword := range keywords {
		rawKeyword, err := strconv.ParseUint(keyword, 0, 64)
		if err != nil {
			continue
		}
		if rawKeyword == keywordAuditFailure {
			outcome = "AUDIT_FAILURE"
		} else if rawKeyword == keywordAuditSuccess {
			outcome = "AUDIT_SUCCESS"
		}

		if name, ok := winMetaKeywords[rawKeyword]; ok {
			finalKeywords = append(finalKeywords, name)
		}
	}

	return finalLevel, opcode, outcome, finalKeywords
}

// formattedBody will parse a body from the event.
func formattedBody(e *EventXML) map[string]any {
	message, details := parseMessage(e.Channel, e.Message)

	level, opcode, outcome, keywords := parseWinMeta(e)

	body := map[string]any{
		"EventID":      e.EventID.ID,
		"SourceName":   e.Provider.Name,
		"ProviderGuid": e.Provider.GUID,
		"EventTime":    e.TimeCreated.SystemTime,
		"EventType":    outcome,
		"Hostname":     e.Computer,
		"Channel":      e.Channel,
		"RecordID":     e.RecordID,
		"Level":        level,
		"LevelValue":   e.Level,
		"Message":      message,
		"Task":         e.RenderedTask,
		"TaskValue":    e.Task,
		"Opcode":       opcode,
		"OpcodeValue":  e.Opcode,
		"Keywords":     keywords,
		"Version":      e.Version,
	}

	if e.Security != nil && e.Security.UserID != "" {
		body["UserID"] = e.Security.UserID
		err := parseSecurityAccount(e.Security)
		if err == nil {
			body["AccountName"] = e.Security.Name
			body["Domain"] = e.Security.Domain
			body["AccountType"] = e.Security.Type
		}
	}

	if len(e.EventData.Data) > 0 {
		for _, data := range e.EventData.Data {
			if data.Name == "Version" || data.Name == "UserID" || data.Name == "AccountName" || data.Name == "Domain" || data.Name == "AccountType" {
				continue // Version is already in the body
			} else {
				body[data.Name] = data.Value
			}
		}
	}

	if len(details) > 0 {
		body["Details"] = details
	}

	if e.Execution != nil {
		//body["execution"] = e.Execution.asMap()

		if e.Execution.ProcessID != 0 {
			body["ProcessID"] = e.Execution.ProcessID
		}

		if e.Execution.ThreadID != 0 {
			body["ThreadID"] = e.Execution.ThreadID
		}

		if e.Execution.ProcessorID != nil {
			body["ProcessorID"] = *e.Execution.ProcessorID
		}

		if e.Execution.SessionID != nil {
			body["SessionID"] = *e.Execution.SessionID
		}

		if e.Execution.KernelTime != nil {
			body["KernelTime"] = *e.Execution.KernelTime
		}

		if e.Execution.UserTime != nil {
			body["UserTime"] = *e.Execution.UserTime
		}

		if e.Execution.ProcessorTime != nil {
			body["ProcessorTime"] = *e.Execution.ProcessorTime
		}
	}

	if e.Correlation != nil {
		body["ActivityID"] = e.Correlation.ActivityID
		body["RelatedActivityID"] = e.Correlation.RelatedActivityID
	}

	return body
}

// parseMessage will attempt to parse a message into a message and details
func parseMessage(channel, message string) (string, map[string]any) {
	switch channel {
	case "Security":
		return parseSecurity(message)
	default:
		return message, nil
	}
}

// EventID is the identifier of the event.
type EventID struct {
	Qualifiers uint16 `xml:"Qualifiers,attr"`
	ID         uint32 `xml:",chardata"`
}

// TimeCreated is the creation time of the event.
type TimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

// Provider is the provider of the event.
type Provider struct {
	Name            string `xml:"Name,attr"`
	GUID            string `xml:"Guid,attr"`
	EventSourceName string `xml:"EventSourceName,attr"`
}

type EventData struct {
	// https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventdatatype-complextype
	// ComplexData is not supported.
	Name   string `xml:"Name,attr"`
	Data   []Data `xml:"Data"`
	Binary string `xml:"Binary"`
}

type Data struct {
	// https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-datafieldtype-complextype
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// Security contains info pertaining to the user triggering the event.
type Security struct {
	UserID string `xml:"UserID,attr"`
	Name   string
	Domain string
	Type   string
}

// parseSecurityAccount will attempt to parse a message into a message and details
func parseSecurityAccount(sid *Security) error {
	if sid == nil || sid.UserID == "" {
		return nil
	}

	s, err := windows.StringToSid(sid.UserID)
	if err != nil {
		return err
	}

	account, domain, accType, err := s.LookupAccount("")
	if err != nil {
		return err
	}

	if typ, found := sidTypeToString[SIDType(accType)]; found {
		sid.Type = typ
	} else if accType > 0 {
		sid.Type = strconv.FormatUint(uint64(accType), 10)
	}

	sid.Name = account
	sid.Domain = domain
	return nil
}

// Correlation contains activity identifiers that consumers can use to group
// related events together.
type Correlation struct {
	ActivityID        string `xml:"ActivityID,attr"`
	RelatedActivityID string `xml:"RelatedActivityID,attr"`
}

// Execution contains info pertaining to the process that triggered the event.
type Execution struct {
	// ProcessID and ThreadID are required on execution info
	ProcessID uint `xml:"ProcessID,attr"`
	ThreadID  uint `xml:"ThreadID,attr"`
	// These remaining fields are all optional for execution info
	ProcessorID   *uint `xml:"ProcessorID,attr"`
	SessionID     *uint `xml:"SessionID,attr"`
	KernelTime    *uint `xml:"KernelTime,attr"`
	UserTime      *uint `xml:"UserTime,attr"`
	ProcessorTime *uint `xml:"ProcessorTime,attr"`
}

// unmarshalEventXML will unmarshal EventXML from xml bytes.
func unmarshalEventXML(bytes []byte) (*EventXML, error) {
	var eventXML EventXML
	if err := xml.Unmarshal(bytes, &eventXML); err != nil {
		return nil, fmt.Errorf("failed to unmarshal xml bytes into event: %w (%s)", err, string(bytes))
	}
	eventXML.Original = string(bytes)
	return &eventXML, nil
}
