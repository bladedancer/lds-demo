package xds

import (
	"fmt"
	"os"
	"time"

	"path/filepath"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt_authn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tls_inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	// Loading these triggers the population of protoregistry via their inits.
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
)

func getSnapshot(customHttpFilters map[string][]*http_conn.HttpFilter) (*cache.Snapshot, error) {
	version := fmt.Sprintf("%d", time.Now().UnixNano())
	log.Infof("version: %s", version)

	filterChains := []*listener.FilterChain{
		newFilterChain("one.example.com", "one", "one", customHttpFilters["one"]),
		newFilterChain("two.example.com", "two", "two", customHttpFilters["two"]),
	}

	lds := []types.Resource{
		newListener("listener1", 8443, filterChains),
	}

	secrets := []types.Resource{
		newSecret("one", "key.pem", "cert.pem", ""),
		newSecret("two", "key.pem", "cert.pem", ""),
	}

	sseRouteOne := newRoute("sseRoute", "/one", "/events", "ssecluster")
	sseRouteTwo := newRoute("sseRoute", "/two", "/events", "ssecluster")
	routes := []types.Resource{
		newRouteConfiguration("one", []string{"one.example.com"}, []*route.Route{sseRouteOne}),
		newRouteConfiguration("two", []string{"two.example.com"}, []*route.Route{sseRouteTwo}),
	}

	clusters := []types.Resource{
		newCluster("ssecluster", "localhost", 8000, false, ""),
	}

	return cache.NewSnapshot(version, map[string][]types.Resource{
		resource.ListenerType: lds,
		resource.SecretType:   secrets,
		resource.RouteType:    routes,
		resource.ClusterType:  clusters,
	})
}

func newListener(name string, port uint32, filterChains []*listener.FilterChain) *listener.Listener {
	tlsInspectorConfig, _ := anypb.New(&tls_inspector.TlsInspector{})
	// Listener
	return &listener.Listener{
		Name: name,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address:  "0.0.0.0",
					Protocol: core.SocketAddress_TCP,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: uint32(port),
					},
				},
			},
		},
		FilterChains: filterChains,
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name:       "envoy.filters.listener.tls_inspector",
				ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: tlsInspectorConfig},
			},
		},
	}
}

func newFilterChain(servername string, routeConfigName string, secretName string, customHttpFilters []*http_conn.HttpFilter) *listener.FilterChain {
	httpFilters := []*http_conn.HttpFilter{}
	if customHttpFilters != nil {
		httpFilters = append(httpFilters, customHttpFilters...)
	}

	routerFilterConfig, _ := anypb.New(&router.Router{})
	httpFilters = append(
		httpFilters,
		&http_conn.HttpFilter{
			Name: wellknown.Router,
			ConfigType: &http_conn.HttpFilter_TypedConfig{
				TypedConfig: routerFilterConfig,
			},
		},
	)

	hcmConfig, err := anypb.New(&http_conn.HttpConnectionManager{
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{},
		Http2ProtocolOptions:      &core.Http2ProtocolOptions{},
		InternalAddressConfig:     &http_conn.HttpConnectionManager_InternalAddressConfig{},
		StatPrefix:                routeConfigName,
		StripMatchingHostPort:     true,
		HttpFilters:               httpFilters,
		RouteSpecifier: &http_conn.HttpConnectionManager_Rds{
			Rds: &http_conn.Rds{
				RouteConfigName: routeConfigName,
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion:    core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_Ads{},
				},
			},
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	filterChain := &listener.FilterChain{
		Filters: []*listener.Filter{
			{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: hcmConfig,
				},
			},
		},
	}

	if secretName != "" {
		downstreamTlsConfig, _ := anypb.New(&secret.DownstreamTlsContext{
			CommonTlsContext: &secret.CommonTlsContext{
				TlsCertificateSdsSecretConfigs: []*secret.SdsSecretConfig{
					{
						Name: secretName,
						SdsConfig: &core.ConfigSource{
							ResourceApiVersion:    core.ApiVersion_V3,
							ConfigSourceSpecifier: &core.ConfigSource_Ads{},
						},
					},
				},
			},
		})

		filterChain.TransportSocket = &core.TransportSocket{
			Name: fmt.Sprintf("ts-%d", time.Now().Unix()),
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: downstreamTlsConfig,
			},
		}
	}

	if servername != "" {
		filterChain.FilterChainMatch = &listener.FilterChainMatch{
			ServerNames: []string{servername},
		}
	}

	return filterChain
}

func newSecret(name string, keyPath string, certPath string, password string) *secret.Secret {
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	return &secret.Secret{
		Name: name,
		Type: &secret.Secret_TlsCertificate{
			TlsCertificate: &secret.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_Filename{
						Filename: filepath.Dir(executable) + "/" + certPath,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_Filename{
						Filename: filepath.Dir(executable) + "/" + keyPath,
					},
				},
				Password: &core.DataSource{
					Specifier: &core.DataSource_InlineString{
						InlineString: password,
					},
				},
			},
		},
	}
}

func newRouteConfiguration(routeConfigName string, domains []string, routes []*route.Route) *route.RouteConfiguration {
	routecfg := &route.RouteConfiguration{
		Name:             routeConfigName,
		ValidateClusters: &wrapperspb.BoolValue{Value: true},
		VirtualHosts: []*route.VirtualHost{
			{
				Name:    routeConfigName,
				Domains: domains,
				Routes:  routes,
			},
		},
	}

	return routecfg
}

func newRoute(name string, prefix string, rewrite string, cluster string) *route.Route {
	return &route.Route{
		Name: name,
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: prefix,
			},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				HostRewriteSpecifier: &route.RouteAction_AutoHostRewrite{AutoHostRewrite: &wrapperspb.BoolValue{Value: true}},
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: cluster,
				},
				PrefixRewrite: rewrite,
				Timeout:       durationpb.New(time.Hour * 1),
			},
		},
	}
}

func newCluster(name string, host string, port uint32, tls bool, mtlsSecretName string) *cluster.Cluster {
	var transportSocket *core.TransportSocket = nil

	if tls {
		mtlsSds := []*secret.SdsSecretConfig{}
		if mtlsSecretName != "" {
			mtlsSds = []*secret.SdsSecretConfig{
				{
					Name: mtlsSecretName,
					SdsConfig: &core.ConfigSource{
						ResourceApiVersion:    core.ApiVersion_V3,
						ConfigSourceSpecifier: &core.ConfigSource_Ads{},
					},
				},
			}
		}
		upstreamTlsConfig, _ := anypb.New(&secret.UpstreamTlsContext{
			CommonTlsContext: &secret.CommonTlsContext{
				TlsCertificateSdsSecretConfigs: mtlsSds,
			},
		})

		transportSocket = &core.TransportSocket{
			Name: name,
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: upstreamTlsConfig,
			},
		}
	}

	return &cluster.Cluster{
		Name:              name,
		WaitForWarmOnInit: &wrapperspb.BoolValue{Value: true},
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_STRICT_DNS,
		},
		ConnectTimeout:  &durationpb.Duration{Seconds: 5},
		TransportSocket: transportSocket,
		DnsLookupFamily: cluster.Cluster_V4_ONLY,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address:       host,
												PortSpecifier: &core.SocketAddress_PortValue{PortValue: port},
												Protocol:      core.SocketAddress_TCP,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func newJwtAuth() *http_conn.HttpFilter {
	jwt, err := anypb.New(&jwt_authn.JwtAuthentication{
		Providers: map[string]*jwt_authn.JwtProvider{
			"okta-jwt": {
				Issuer: "https://dev-94945820.okta.com/oauth2/authserver",
				Audiences: []string{
					"api://authserver",
				},
				PayloadInMetadata:    "jwt_payload",
				ForwardPayloadHeader: "x-axway-jwt-payload",
				JwksSourceSpecifier: &jwt_authn.JwtProvider_RemoteJwks{
					RemoteJwks: &jwt_authn.RemoteJwks{
						HttpUri: &core.HttpUri{
							Uri:              "https://dev-94945820.okta.com/oauth2/authserver/v1/keys",
							Timeout:          durationpb.New(time.Millisecond * 10000),
							HttpUpstreamType: &core.HttpUri_Cluster{Cluster: "jwks_cluster"},
						},
					},
				},
				FromHeaders: []*jwt_authn.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
			},
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	httpFilter := &http_conn.HttpFilter{
		Name: "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
		ConfigType: &http_conn.HttpFilter_TypedConfig{
			TypedConfig: jwt,
		},
	}

	return httpFilter
}
