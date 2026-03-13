package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDashboardStats(t *testing.T) {
	req := v2.DashboardStatsReq{
		Domain: "all", // Or a specific domain known to exist in your test environment
	}

	Convey("Test API DashboardStats", t, func() {
		resp, err := ADACli.cli.DashboardStats(ADACli.ctx, &req)

		Convey("Check for gRPC errors", func() {
			So(err, ShouldBeNil)
		})
		if err != nil || resp == nil {
			return
		}

		Convey("Check response validity", func() {
			So(resp, ShouldNotBeNil)

			// Check asset counts
			if total, ok := resp.Asset["total"]; ok {
				So(total, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("Asset Total: %d\n", total)
			}
			if today, ok := resp.Asset["today"]; ok {
				So(today, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("Asset Today: %d\n", today)
			}

			// Check alert counts by level
			fmt.Println("Alert counts by level:")
			for level, count := range resp.Alert {
				So(count, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("  %s: %d\n", level, count)
			}

			// Check baseline counts by level
			fmt.Println("Baseline counts by level:")
			for level, count := range resp.Baseline {
				So(count, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("  %s: %d\n", level, count)
			}

			// Check leak counts by level
			fmt.Println("Leak counts by level:")
			for level, count := range resp.Leak {
				So(count, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("  %s: %d\n", level, count)
			}

			// Check weakpwd counts
			fmt.Println("Weak password counts:")
			for key, count := range resp.Weakpwd {
				So(count, ShouldBeGreaterThanOrEqualTo, 0)
				fmt.Printf("  %s: %d\n", key, count)
			}
		})

		// Log the complete response for inspection
		fmt.Printf("\nComplete DashboardStats Response:\n")
		fmt.Printf("Asset: %+v\n", resp.Asset)
		fmt.Printf("Alert: %+v\n", resp.Alert)
		fmt.Printf("Baseline: %+v\n", resp.Baseline)
		fmt.Printf("Leak: %+v\n", resp.Leak)
		fmt.Printf("Weakpwd: %+v\n", resp.Weakpwd)
	})
}

func TestDashboardLogStats(t *testing.T) {
	// It's assumed ADACli and ADACli.ctx are initialized similarly to domain_test.go
	// You might need a setup function (e.g., TestMain) if not already present.

	req := v2.DashboardLogStatsReq{
		Domain:   "all", // Or a specific domain known to exist in your test environment
		Duration: 3,     // Request stats for the last 1 hour, valid values: 1/3/6/12/24
	}

	Convey("Test API DashboardLogStats", t, func() {
		resp, err := ADACli.cli.DashboardLogStats(ADACli.ctx, &req)

		Convey("Check for gRPC errors", func() {
			So(err, ShouldBeNil)
		})
		if err != nil || resp == nil {
			return
		}

		Convey("Check response validity", func() {
			So(resp, ShouldNotBeNil)
			So(resp.List, ShouldNotBeNil)

			// Optional: Check if the list length matches the expected duration (in minutes)
			// This might be brittle depending on data availability.
			expectedLen := req.Duration*60 + 1
			So(len(resp.List), ShouldEqual, expectedLen)

			// Optional: Check individual items if needed
			if len(resp.List) > 0 {
				firstItem := resp.List[0]
				So(firstItem, ShouldNotBeNil)
				So(firstItem.Ts, ShouldBeGreaterThan, 0) // Timestamp should be positive
				So(firstItem.WinlogCounts, ShouldBeGreaterThanOrEqualTo, 0)
				So(firstItem.PktlogCounts, ShouldBeGreaterThanOrEqualTo, 0)
			}
		})

		for _, item := range resp.List {
			fmt.Printf("Timestamp: %d, Winlog Counts: %d, Pktlog Counts: %d\n", item.Ts, item.WinlogCounts, item.PktlogCounts)
		}

		// Log the response for inspection
		//t.Logf("DashboardLogStats Response: %+v", resp)
	})
}
