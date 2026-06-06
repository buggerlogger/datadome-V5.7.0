package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/L0ed0/datadome-solver/internal/builder"
	ddcrypto "github.com/L0ed0/datadome-solver/internal/crypto"
	"github.com/L0ed0/datadome-solver/pkg/solver"
)

func main() {
	site := flag.String("site", "", "Target site URL (required)")
	proxy := flag.String("proxy", "", "HTTP/SOCKS proxy URL")
	profile := flag.String("profile", "chrome_win10", "Browser profile name")
	key := flag.String("key", "", "DataDome JS key (ddk)")
	cid := flag.String("cid", "", "Existing DataDome CID")
	tagsURL := flag.String("tags-url", "", "Custom tags.js POST endpoint")
	solve := flag.Bool("solve", false, "Solve and print cookie")
	verify := flag.Bool("verify", false, "Solve, then verify cookie with GET request")
	twoPhase := flag.Bool("two-phase", false, "Two-phase solve (initial + behavioral)")
	delay := flag.Int("delay", 10, "Delay between phases in seconds")
	bpc := flag.Int("bpc", 1, "BPC value (1=initial, 2+=behavioral)")
	jsType := flag.String("jstype", "ch", "jsType field value")
	eventCounters := flag.String("event-counters", "[]", "Event counters JSON")
	seed := flag.Int64("seed", 0, "PRNG seed for reproducible output")
	encrypt := flag.Bool("encrypt", false, "Print encrypted jspl only")
	output := flag.String("output", "", "Write payload JSON to file")
	flag.Parse()

	if *site == "" {
		fmt.Fprintln(os.Stderr, "error: -site is required")
		flag.Usage()
		os.Exit(2)
	}

	if *solve || *verify || *twoPhase {
		runSolver(*site, *key, *cid, *proxy, *profile, *tagsURL, *bpc, *jsType, *eventCounters, *delay, *twoPhase, *verify)
		return
	}

	signals := builder.BuildPayload(builder.Options{
		Profile: *profile, URL: *site, BPC: *bpc, Seed: *seed,
	})

	if *encrypt {
		if *key == "" {
			fatal("error: -key is required with -encrypt")
		}
		jspl, err := ddcrypto.Encrypt(signals, *key, *cid, nil)
		if err != nil {
			fatal("encrypt: %v", err)
		}
		fmt.Println(jspl)
		return
	}

	m := make(map[string]any, len(signals))
	for _, s := range signals {
		m[s.Key] = s.Value
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fatal("write: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d signals to %s\n", len(signals), *output)
		return
	}
	fmt.Print(string(data))
}

func runSolver(site, key, cid, proxy, profile, tagsURL string, bpc int, jsType, eventCounters string, delaySec int, twoPhase, doVerify bool) {
	if key == "" {
		fatal("error: -key is required with -solve/-verify/-two-phase")
	}

	opts := []solver.Option{
		solver.WithDDJSKey(key),
		solver.WithProfile(profile),
	}
	if cid != "" {
		opts = append(opts, solver.WithCID(cid))
	}
	if proxy != "" {
		opts = append(opts, solver.WithProxy(proxy))
	}
	if tagsURL != "" {
		opts = append(opts, solver.WithTagsURL(tagsURL))
	}

	client, err := solver.New(site, opts...)
	if err != nil {
		fatal("error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(delaySec+30)*time.Second)
	defer cancel()

	var result *solver.Result

	if twoPhase {
		result, err = client.SolveTwoPhase(ctx, time.Duration(delaySec)*time.Second, eventCounters)
	} else {
		result, err = client.SolveWith(ctx, solver.SolveOptions{
			BPC: bpc, JsType: jsType, EventCounters: eventCounters,
		})
	}

	if err != nil {
		fatal("error: %v", err)
	}
	fmt.Println(result.Cookie)

	if doVerify {
		verifyCookie(client, result.Cookie)
	}
}

func verifyCookie(client *solver.Client, cookieHeader string) {
	cookieVal := strings.SplitN(cookieHeader, ";", 2)[0]

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	status, _, err := client.Verify(ctx, cookieVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "GET /: %d\n", status)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()

	scrapingURL := strings.TrimSuffix(client.SiteURL, "/") + "/scraping"
	status2, _, err2 := client.VerifyURL(ctx2, cookieVal, scrapingURL)
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "verify /scraping error: %v\n", err2)
		return
	}
	fmt.Fprintf(os.Stderr, "GET /scraping: %d\n", status2)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
