package xds

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	// Loading these triggers the population of protoregistry via their inits.
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
)

func streamOpenFunc(ctx context.Context, i int64, s string) error {
	log.Infof("streamOpenFunc %d %s", i, s)
	return nil
}

func streamClosedFunc(i int64, node *core.Node) {
	log.Infof("streamClosedFunc %d", i)
}

func streamRequestFunc(i int64, req *discovery.DiscoveryRequest) error {
	if req.ErrorDetail != nil {
		log.Errorf("%+v", req.ErrorDetail)
	}
	log.Infof("streamRequestFunc %d %s", i, req.TypeUrl)
	return nil
}

func streamResponseFunc(ctx context.Context, i int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	log.Infof("streamResponseFunc %d %s %d", i, req.TypeUrl, len(resp.Resources))
}

func deltaStreamOpenFunc(ctx context.Context, i int64, s string) error {
	log.Infof("deltaStreamOpenFunc %d %s", i, s)
	return nil
}

func deltaStreamClosedFunc(i int64, node *core.Node) {
	log.Infof("deltaStreamClosedFunc %d", i)
}

func streamDeltaRequestFunc(i int64, req *discovery.DeltaDiscoveryRequest) error {
	if req.ErrorDetail != nil {
		log.Errorf("%+v", req.ErrorDetail)
	}
	log.Infof("streamDeltaRequestFunc %d %s", i, req.TypeUrl)
	return nil
}

func streamDeltaResponseFunc(i int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	log.Infof("streamDeltaResponseFunc %d %s %d", i, req.TypeUrl, len(resp.Resources))
}

// Run entry point for Envoy XDS command line.
func Run() error {

	callbacks := server.CallbackFuncs{
		DeltaStreamOpenFunc:     deltaStreamOpenFunc,
		DeltaStreamClosedFunc:   deltaStreamClosedFunc,
		StreamDeltaRequestFunc:  streamDeltaRequestFunc,
		StreamDeltaResponseFunc: streamDeltaResponseFunc,
		StreamOpenFunc:          streamOpenFunc,
		StreamClosedFunc:        streamClosedFunc,
		StreamRequestFunc:       streamRequestFunc,
		StreamResponseFunc:      streamResponseFunc,
	}

	snapshotCache := cache.NewSnapshotCache(true, cache.IDHash{}, log)

	server := serverv3.NewServer(context.Background(), snapshotCache, callbacks)
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Port))
	if err != nil {
		log.Fatal(err)
	}

	//extension.RegisterExtensionConfigDiscoveryServiceServer(grpcServer, server)
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)

	go func() {
		if err = grpcServer.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()

	log.Infof("Listening on %d", config.Port)
	triggerUpdate := StartSnapshotting(context.Background(), snapshotCache)
	process(triggerUpdate)
	grpcServer.GracefulStop()
	log.Info("Shutdown")
	return nil
}

func process(triggerUpdate chan map[string][]*http_conn.HttpFilter) {
	fmt.Println("Press [s] to trigger snapshot, [u] to trigger updated snapshot, [q] to quit")
	// switch stdin into 'raw' mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	for {
		inChan := readInput()
		select {
		case opt := <-inChan:
			if opt == "s" {
				triggerUpdate <- map[string][]*http_conn.HttpFilter{}
			} else if opt == "u" {
				log.Info("UPDATING TWO")
				updates := map[string][]*http_conn.HttpFilter{}
				updates["two"] = []*http_conn.HttpFilter{newJwtAuth()}
				triggerUpdate <- updates
			} else if opt == "q" {
				return
			}
		case <-done:
			return
		}
	}
}

func readInput() chan string {
	charChan := make(chan string)
	go func() {
		b := make([]byte, 1)
		os.Stdin.Read(b)
		charChan <- string(b[0])
	}()

	return charChan
}

func StartSnapshotting(ctx context.Context, snapshotCache cache.SnapshotCache) chan map[string][]*http_conn.HttpFilter {
	trigger := make(chan map[string][]*http_conn.HttpFilter)

	go func() {
		for {
			select {
			case customHttpFilters := <-trigger:
				snapshot, err := getSnapshot(customHttpFilters)
				if err != nil {
					log.Errorf("%+v", err)
					return
				}
				snapshotCache.SetSnapshot(ctx, "ldsdemo", snapshot)
			case <-ctx.Done():
				return
			}
		}
	}()

	return trigger
}
